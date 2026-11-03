"""Fail-closed admission for one issue run."""

from __future__ import annotations

from dataclasses import replace

from factory import budget, config as config_module, gitio
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.limits import parse_count, parse_duration
from factory.model import TERMINAL_STOPS, BudgetPosition, Counters, Limits, Run
from factory.paths import RuntimePaths
from factory.store import load_run, save_run

ACTIVE = ("ready", "red", "gates", "green", "local-verified")
MODEL_ATTESTATION = "operator-declared; the factory never contacts a model or verifies an account"


def _limits(args: object) -> Limits:
    seconds = parse_duration(str(getattr(args, "time_limit")))
    operations = parse_count(str(getattr(args, "operation_limit")), "operation limit")
    turn_raw = getattr(args, "supervision_turns")
    write_raw = getattr(args, "supervision_writes")
    if seconds <= 0:
        raise UsageError("time limit must be greater than zero")
    if operations <= 0:
        raise UsageError("operation limit must be greater than zero")
    turns = parse_count(str(turn_raw), "turn limit") if turn_raw is not None else None
    writes = parse_count(str(write_raw), "write limit") if write_raw is not None else None
    return Limits(
        time_seconds=seconds,
        operations=operations,
        supervision_turns=turns,
        supervision_writes=writes,
    )


def _unknown_position(conf: config_module.Config) -> BudgetPosition | None:
    if not conf.budget.timezone:
        return None
    try:
        week = budget.week_key(conf.budget)
    except UsageError:
        return None
    return BudgetPosition(
        week=week,
        state="unknown",
        usd=None,
        source=None,
        recorded_at=None,
        verification="operator-declared; not independently verified",
        weekly_usd=conf.budget.weekly_usd,
        bugfix_usd=conf.budget.bugfix_usd,
        stop_usd=conf.budget.stop_usd,
    )


def _scaffold(
    paths: RuntimePaths,
    args: object,
    *,
    head: str,
    base_branch: str,
    limits: Limits,
    digest: str,
    budget_position: BudgetPosition | None,
    counters: Counters,
    created_at: str,
    execution_profile: str,
    profile_attestation: object,
) -> Run:
    issue = int(getattr(args, "issue"))
    return Run(
        schema=1,
        issue=issue,
        feature=str(getattr(args, "feature")).strip(),
        kind=str(getattr(args, "kind")),
        declared_model=str(getattr(args, "model")).strip(),
        model_attestation=MODEL_ATTESTATION,
        branch=f"run-issue-{issue}",
        base_sha=head,
        base_branch=base_branch,
        phase="unadmitted",
        admitted_at=None,
        gate_digest=digest,
        budget=budget_position,
        limits=limits,
        counters=counters,
        red_sha=None,
        green_sha=None,
        expected_green_sha=None,
        red=None,
        stage=None,
        green=None,
        evidence_dir=str(paths.issue_evidence(issue)),
        created_at=created_at,
        execution_profile=execution_profile,
        profile_attestation=profile_attestation,
    )


def _stop_new(paths: RuntimePaths, run: Run, reason: str, detail: str) -> Run:
    return save_run(
        paths,
        replace(
            run,
            phase="stopped",
            stop_reason=reason,
            stop_detail=detail,
            prior_phase="unadmitted",
            stopped_at=now(),
        ),
    )


def prepare(paths: RuntimePaths, args: object) -> Run:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    if not bool(getattr(args, "attest_model_account")):
        raise UsageError("prepare needs --attest-model-account; the model account is operator-declared, not observed")
    limits = _limits(args)
    issue = int(getattr(args, "issue"))
    if not str(getattr(args, "feature") or "").strip():
        raise UsageError("prepare needs a non-empty --feature")
    if not str(getattr(args, "model") or "").strip():
        raise UsageError("prepare needs a non-empty --model")
    gitio.require_clean(paths.repo)
    head = gitio.head(paths.repo)
    current = gitio.branch(paths.repo)
    if not current:
        raise UsageError("prepare needs a checked-out branch; detached HEAD is refused")
    existing = load_run(paths, issue)
    if existing is not None:
        if existing.phase in ACTIVE:
            raise UsageError(f"issue {issue} is already {existing.phase}; resume or stop it instead")
        if existing.phase == "stopped" and existing.stop_reason in TERMINAL_STOPS:
            raise UsageError(f"issue {issue} stopped terminally: {existing.stop_reason}")
        if existing.phase == "stopped" and existing.prior_phase in ("red", "gates", "green", "local-verified"):
            raise UsageError(f"issue {issue} stopped mid-run; use resume, not prepare")
    counters = existing.counters if existing is not None else Counters()
    created_at = existing.created_at if existing is not None else now()
    digest = config_module.digest(conf)
    scaffold = dict(
        head=head,
        base_branch=current,
        limits=limits,
        digest=digest,
        budget_position=_unknown_position(conf),
        counters=counters,
        created_at=created_at,
        execution_profile=conf.execution_profile,
        profile_attestation=conf.native_turbo_attestation,
    )

    issues = config_module.completeness_issues(conf)
    if issues:
        run = _stop_new(paths, _scaffold(paths, args, **scaffold), "missing", "; ".join(issues))
        raise PolicyError(f"admission stopped for issue {run.issue}: missing ({'; '.join(issues)})")

    branch = f"run-issue-{issue}"
    if gitio.branch_exists(paths.repo, branch):
        run = _stop_new(paths, _scaffold(paths, args, **scaffold), "missing", f"branch {branch} already exists")
        raise PolicyError(f"admission stopped for issue {issue}: branch {branch} already exists")

    try:
        position = budget.attestation(conf.budget, str(getattr(args, "kind")))
    except PolicyError as exc:
        run = _stop_new(paths, _scaffold(paths, args, **scaffold), "budget", str(exc))
        raise PolicyError(f"admission stopped for issue {run.issue}: budget: {exc}") from exc

    ready = replace(
        _scaffold(paths, args, **{**scaffold, "budget_position": position}),
        phase="ready",
        admitted_at=now(),
        stop_reason=None,
        stop_detail=None,
        prior_phase=None,
        stopped_at=None,
    )
    return save_run(paths, ready)
