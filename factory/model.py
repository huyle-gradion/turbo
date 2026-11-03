"""Typed run state. Every stored document is parsed once at the boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from factory.errors import CorruptState
from factory.gate_records import GateAttempt, GateObservation, GreenEvidence, ReplayEvidence, ResumeEntry
from factory.jsonshape import integer, items, mapping, number, strings, text
from factory import profile as profile_module

SCHEMA = 1
PHASES = ("unadmitted", "ready", "red", "gates", "green", "local-verified", "stopped")
STOP_REASONS = ("budget", "missing", "not-ready", "cancelled", "retry-cap", "superseded")
RECOVERABLE_STOPS = ("budget", "missing", "not-ready")
TERMINAL_STOPS = ("cancelled", "retry-cap", "superseded")
REPAIR_CAP = 2


@dataclass(frozen=True, slots=True)
class TestIdentity:
    file: str
    selector: str
    command: str
    blob_sha256: str

    @classmethod
    def from_dict(cls, data: Any) -> TestIdentity:
        raw = mapping(data, "test identity")
        return cls(
            file=str(text(raw.get("file"), "test.file")),
            selector=str(text(raw.get("selector"), "test.selector")),
            command=str(text(raw.get("command"), "test.command")),
            blob_sha256=str(text(raw.get("blob_sha256"), "test.blob_sha256")),
        )


@dataclass(frozen=True, slots=True)
class Limits:
    time_seconds: int
    operations: int
    supervision_turns: int | None
    supervision_writes: int | None

    @classmethod
    def from_dict(cls, data: Any) -> Limits:
        raw = mapping(data, "limits")
        time_seconds = int(integer(raw.get("time_seconds"), "time_seconds"))
        operations = int(integer(raw.get("operations"), "operations"))
        turns = integer(raw.get("supervision_turns"), "supervision_turns", optional=True)
        writes = integer(raw.get("supervision_writes"), "supervision_writes", optional=True)
        bounds = (("time_seconds", time_seconds, 1), ("operations", operations, 1),
                  ("supervision_turns", turns, 0), ("supervision_writes", writes, 0))
        for name, value, floor in bounds:
            if value is not None and value < floor:
                raise CorruptState(f"{name} must be at least {floor}")
        return cls(
            time_seconds=time_seconds, operations=operations,
            supervision_turns=turns, supervision_writes=writes,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["enforcement"] = {
            "time_seconds": "checked before each helper action",
            "operations": "enforced for observed child commands",
            "supervision_turns": "not enforced; operator supervision only",
            "supervision_writes": "not enforced; the factory never claims file-write counts",
        }
        return payload


@dataclass(frozen=True, slots=True)
class Counters:
    operations_used: int = 0
    repairs_used: int = 0
    repair_cap: int = REPAIR_CAP

    @classmethod
    def from_dict(cls, data: Any) -> Counters:
        raw = mapping(data, "counters")
        operations_used = int(integer(raw.get("operations_used", 0), "operations_used"))
        repairs_used = int(integer(raw.get("repairs_used", 0), "repairs_used"))
        repair_cap = int(integer(raw.get("repair_cap", REPAIR_CAP), "repair_cap"))
        for name, value in (
            ("operations_used", operations_used),
            ("repairs_used", repairs_used),
            ("repair_cap", repair_cap),
        ):
            if value < 0:
                raise CorruptState(f"{name} must be a non-negative integer")
        return cls(operations_used=operations_used, repairs_used=repairs_used, repair_cap=repair_cap)


@dataclass(frozen=True, slots=True)
class BudgetPosition:
    week: str
    state: str
    usd: float | None
    source: str | None
    recorded_at: str | None
    verification: str
    weekly_usd: float
    bugfix_usd: float
    stop_usd: float

    @classmethod
    def from_dict(cls, data: Any) -> BudgetPosition:
        raw = mapping(data, "budget")
        state = str(text(raw.get("state"), "budget.state"))
        if state not in ("known", "unknown"):
            raise CorruptState(f"budget state invalid: {state}")
        return cls(
            week=str(text(raw.get("week"), "budget.week")),
            state=state,
            usd=number(raw.get("usd"), "budget.usd", optional=True),
            source=text(raw.get("source"), "budget.source", optional=True),
            recorded_at=text(raw.get("recorded_at"), "budget.recorded_at", optional=True),
            verification=str(text(raw.get("verification"), "budget.verification")),
            weekly_usd=float(number(raw.get("weekly_usd"), "budget.weekly_usd")),
            bugfix_usd=float(number(raw.get("bugfix_usd"), "budget.bugfix_usd")),
            stop_usd=float(number(raw.get("stop_usd"), "budget.stop_usd")),
        )


@dataclass(frozen=True, slots=True)
class RedEvidence:
    test: TestIdentity
    command: str
    argv: tuple[str, ...]
    expect: str
    exit: int
    output_sha256: str
    output_path: str
    at: str
    head_sha: str
    provenance: str

    @classmethod
    def from_dict(cls, data: Any) -> RedEvidence:
        raw = mapping(data, "red evidence")
        return cls(
            test=TestIdentity.from_dict(raw.get("test")),
            command=str(text(raw.get("command"), "red.command")),
            argv=strings(raw.get("argv"), "red.argv"),
            expect=str(text(raw.get("expect"), "red.expect")),
            exit=int(integer(raw.get("exit"), "red.exit")),
            output_sha256=str(text(raw.get("output_sha256"), "red.output_sha256")),
            output_path=str(text(raw.get("output_path"), "red.output_path")),
            at=str(text(raw.get("at"), "red.at")),
            head_sha=str(text(raw.get("head_sha"), "red.head_sha")),
            provenance=str(text(raw.get("provenance"), "red.provenance")),
        )


@dataclass(frozen=True, slots=True)
class StageContract:
    expected_head: str
    red_sha: str
    test_blob_sha256: str
    recorded_at: str

    @classmethod
    def from_dict(cls, data: Any) -> StageContract:
        raw = mapping(data, "stage contract")
        return cls(
            expected_head=str(text(raw.get("expected_head"), "stage.expected_head")),
            red_sha=str(text(raw.get("red_sha"), "stage.red_sha")),
            test_blob_sha256=str(text(raw.get("test_blob_sha256"), "stage.test_blob_sha256")),
            recorded_at=str(text(raw.get("recorded_at"), "stage.recorded_at")),
        )


@dataclass(frozen=True, slots=True)
class Run:
    schema: int
    issue: int
    feature: str
    kind: str
    declared_model: str
    model_attestation: str
    branch: str
    base_sha: str
    base_branch: str
    phase: str
    admitted_at: str | None
    gate_digest: str
    budget: BudgetPosition | None
    limits: Limits | None
    counters: Counters
    red_sha: str | None
    green_sha: str | None
    expected_green_sha: str | None
    red: RedEvidence | None
    stage: StageContract | None
    green: GreenEvidence | None
    replay: ReplayEvidence | None = None
    gate_chain: tuple[str, ...] = field(default_factory=tuple)
    gate_attempts: tuple[GateAttempt, ...] = field(default_factory=tuple)
    gate_observations: tuple[GateObservation, ...] = field(default_factory=tuple)
    stop_reason: str | None = None
    stop_detail: str | None = None
    prior_phase: str | None = None
    stopped_at: str | None = None
    evidence_dir: str = ""
    manifest_path: str | None = None
    resume_history: tuple[ResumeEntry, ...] = field(default_factory=tuple)
    created_at: str = ""
    updated_at: str = ""
    execution_profile: str = profile_module.DEFAULT_PROFILE
    profile_attestation: profile_module.NativeTurboAttestation | None = None
    verified_by: str = profile_module.VERIFIED_BY_MANUAL

    @classmethod
    def from_dict(cls, data: Any) -> Run:
        raw = mapping(data, "run")
        if raw.get("schema") != SCHEMA:
            raise CorruptState(f"unsupported run schema: {raw.get('schema')!r}")
        if (phase := str(text(raw.get("phase"), "phase"))) not in PHASES:
            raise CorruptState(f"unknown phase: {phase}")
        if (kind := str(text(raw.get("kind"), "kind"))) not in ("bug", "feature"):
            raise CorruptState(f"unknown issue kind: {kind}")
        if (stop_reason := text(raw.get("stop_reason"), "stop_reason", optional=True)) is not None and stop_reason not in STOP_REASONS:
            raise CorruptState(f"unknown stop reason: {stop_reason}")
        prior_phase = text(raw.get("prior_phase"), "prior_phase", optional=True)
        if prior_phase is not None and (prior_phase not in PHASES or prior_phase == "stopped"):
            raise CorruptState(f"unknown prior phase: {prior_phase}")
        if phase == "stopped" and (stop_reason is None or prior_phase is None):
            raise CorruptState("a stopped run needs stop_reason and prior_phase")
        budget_raw, limits_raw = raw.get("budget"), raw.get("limits")
        execution_profile, profile_attestation, verified_by = profile_module.parse_run_identity(raw)
        return cls(
            schema=SCHEMA,
            issue=int(integer(raw.get("issue"), "issue")),
            feature=str(text(raw.get("feature"), "feature")),
            kind=kind,
            declared_model=str(text(raw.get("declared_model"), "declared_model")),
            model_attestation=str(text(raw.get("model_attestation"), "model_attestation")),
            branch=str(text(raw.get("branch"), "branch")),
            base_sha=str(text(raw.get("base_sha"), "base_sha")),
            base_branch=str(text(raw.get("base_branch"), "base_branch")),
            phase=phase,
            admitted_at=text(raw.get("admitted_at"), "admitted_at", optional=True),
            gate_digest=str(text(raw.get("gate_digest"), "gate_digest")),
            budget=None if budget_raw is None else BudgetPosition.from_dict(budget_raw),
            limits=None if limits_raw is None else Limits.from_dict(limits_raw),
            counters=Counters.from_dict(raw.get("counters", {})),
            red_sha=text(raw.get("red_sha"), "red_sha", optional=True),
            green_sha=text(raw.get("green_sha"), "green_sha", optional=True),
            expected_green_sha=text(raw.get("expected_green_sha"), "expected_green_sha", optional=True),
            red=None if raw.get("red") is None else RedEvidence.from_dict(raw.get("red")),
            stage=None if raw.get("stage") is None else StageContract.from_dict(raw.get("stage")),
            green=None if raw.get("green") is None else GreenEvidence.from_dict(raw.get("green")),
            replay=None if raw.get("replay") is None else ReplayEvidence.from_dict(raw.get("replay")),
            gate_chain=strings(raw.get("gate_chain", []), "gate_chain"),
            gate_attempts=tuple(GateAttempt.from_dict(item) for item in items(raw.get("gate_attempts", []), "gate_attempts")),
            gate_observations=tuple(GateObservation.from_dict(item) for item in items(raw.get("gate_observations", []), "gate_observations")),
            stop_reason=stop_reason,
            stop_detail=text(raw.get("stop_detail"), "stop_detail", optional=True),
            prior_phase=prior_phase,
            stopped_at=text(raw.get("stopped_at"), "stopped_at", optional=True),
            evidence_dir=str(text(raw.get("evidence_dir"), "evidence_dir")),
            manifest_path=text(raw.get("manifest_path"), "manifest_path", optional=True),
            resume_history=tuple(ResumeEntry.from_dict(item) for item in items(raw.get("resume_history", []), "resume_history")),
            created_at=str(text(raw.get("created_at"), "created_at")),
            updated_at=str(text(raw.get("updated_at"), "updated_at")),
            execution_profile=execution_profile,
            profile_attestation=profile_attestation,
            verified_by=verified_by,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if self.limits is not None:
            payload["limits"] = self.limits.to_dict()
        return payload
