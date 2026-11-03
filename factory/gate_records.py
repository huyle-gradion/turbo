"""Gate and resume records nested inside a run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from factory.jsonshape import integer, items, mapping, strings, text, text_or_empty


@dataclass(frozen=True, slots=True)
class GateObservation:
    gate: str
    kind: str
    argv: tuple[str, ...]
    exit: int
    output_sha256: str
    output_path: str
    at: str
    duration_ms: int
    head_sha: str
    test_blob_sha256: str
    gate_digest: str
    provenance: str

    @classmethod
    def from_dict(cls, data: Any) -> GateObservation:
        raw = mapping(data, "gate observation")
        return cls(
            gate=str(text(raw.get("gate"), "gate.gate")),
            kind=str(text(raw.get("kind"), "gate.kind")),
            argv=strings(raw.get("argv"), "gate.argv"),
            exit=int(integer(raw.get("exit"), "gate.exit")),
            output_sha256=str(text(raw.get("output_sha256"), "gate.output_sha256")),
            output_path=str(text(raw.get("output_path"), "gate.output_path")),
            at=str(text(raw.get("at"), "gate.at")),
            duration_ms=int(integer(raw.get("duration_ms"), "gate.duration_ms")),
            head_sha=str(text(raw.get("head_sha"), "gate.head_sha")),
            test_blob_sha256=str(text(raw.get("test_blob_sha256"), "gate.test_blob_sha256")),
            gate_digest=str(text(raw.get("gate_digest"), "gate.gate_digest")),
            provenance=str(text(raw.get("provenance"), "gate.provenance")),
        )


@dataclass(frozen=True, slots=True)
class GateAttempt:
    gate: str
    at: str
    reason: str
    head_sha: str

    @classmethod
    def from_dict(cls, data: Any) -> GateAttempt:
        raw = mapping(data, "gate attempt")
        return cls(
            gate=str(text(raw.get("gate"), "attempt.gate")),
            at=str(text(raw.get("at"), "attempt.at")),
            reason=str(text(raw.get("reason"), "attempt.reason")),
            head_sha=str(text(raw.get("head_sha"), "attempt.head_sha")),
        )


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    head_sha: str
    argv: tuple[str, ...]
    selector: str
    exit: int
    output_sha256: str
    output_path: str
    at: str
    duration_ms: int
    test_blob_sha256: str
    gate_digest: str
    provenance: str

    @classmethod
    def from_dict(cls, data: Any) -> ReplayEvidence:
        raw = mapping(data, "replay evidence")
        return cls(
            head_sha=str(text(raw.get("head_sha"), "replay.head_sha")),
            argv=strings(raw.get("argv"), "replay.argv"),
            selector=str(text(raw.get("selector"), "replay.selector")),
            exit=int(integer(raw.get("exit"), "replay.exit")),
            output_sha256=str(text(raw.get("output_sha256"), "replay.output_sha256")),
            output_path=str(text(raw.get("output_path"), "replay.output_path")),
            at=str(text(raw.get("at"), "replay.at")),
            duration_ms=int(integer(raw.get("duration_ms"), "replay.duration_ms")),
            test_blob_sha256=str(text(raw.get("test_blob_sha256"), "replay.test_blob_sha256")),
            gate_digest=str(text(raw.get("gate_digest"), "replay.gate_digest")),
            provenance=str(text(raw.get("provenance"), "replay.provenance")),
        )


@dataclass(frozen=True, slots=True)
class GreenEvidence:
    head_sha: str
    test_blob_sha256: str
    gate_digest: str
    at: str
    observations: tuple[GateObservation, ...]
    provenance: str

    @classmethod
    def from_dict(cls, data: Any) -> GreenEvidence:
        raw = mapping(data, "green evidence")
        return cls(
            head_sha=str(text(raw.get("head_sha"), "green.head_sha")),
            test_blob_sha256=str(text(raw.get("test_blob_sha256"), "green.test_blob_sha256")),
            gate_digest=str(text(raw.get("gate_digest"), "green.gate_digest")),
            at=str(text(raw.get("at"), "green.at")),
            observations=tuple(GateObservation.from_dict(item) for item in items(raw.get("observations"), "green.observations")),
            provenance=str(text(raw.get("provenance"), "green.provenance")),
        )


@dataclass(frozen=True, slots=True)
class ResumeEntry:
    at: str
    verdict: str
    reasons: tuple[str, ...]
    pr: str
    head_sha: str
    branch: str
    dirty: bool
    previous_phase: str

    @classmethod
    def from_dict(cls, data: Any) -> ResumeEntry:
        raw = mapping(data, "resume entry")
        return cls(
            at=str(text(raw.get("at"), "resume.at")),
            verdict=str(text(raw.get("verdict"), "resume.verdict")),
            reasons=strings(raw.get("reasons"), "resume.reasons"),
            pr=str(text(raw.get("pr"), "resume.pr")),
            head_sha=text_or_empty(raw.get("head_sha"), "resume.head_sha"),
            branch=text_or_empty(raw.get("branch"), "resume.branch"),
            dirty=bool(raw.get("dirty", False)),
            previous_phase=str(text(raw.get("previous_phase"), "resume.previous_phase")),
        )
