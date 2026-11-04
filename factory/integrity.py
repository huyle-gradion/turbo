"""Raw evidence artifact and manifest integrity checks.

Recorded JSON is a claim about bytes on disk. Every check here reads those bytes again: the
artifact must be a regular file inside the private home, and its SHA-256 must equal the recorded
digest. A modified, deleted, or symlinked artifact refuses the step that would certify it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict
from pathlib import Path

from factory.errors import CorruptState, PolicyError, UsageError
from factory.model import BudgetPosition, Run

GATES = ("1", "2", "3")


def _require_regular(path_text: str, home: Path) -> Path:
    path = Path(path_text)
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise UsageError(f"required evidence artifact is missing: {path}") from exc
    except OSError as exc:
        raise UsageError(f"cannot stat evidence artifact {path}: {exc.strerror}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise UsageError(f"evidence artifact is a symlink and is refused: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise UsageError(f"evidence artifact is not a regular file: {path}")
    if not path.resolve().is_relative_to(home.resolve()):
        raise UsageError(f"evidence artifact escapes the private home: {path}")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_artifact(path_text: str, expected_sha: str, home: Path, label: str) -> Path:
    path = _require_regular(path_text, home)
    actual = digest(path)
    if actual != expected_sha:
        raise UsageError(
            f"{label} artifact digest mismatch: {path} recorded {expected_sha} but now hashes to {actual}"
        )
    return path


def require_red(run: Run, home: Path) -> Path:
    if run.red is None:
        raise UsageError("red evidence is missing from the run record")
    return require_artifact(run.red.output_path, run.red.output_sha256, home, "red")


def require_replay(run: Run, home: Path) -> Path:
    if run.replay is None:
        raise PolicyError("no replay recorded; run `factory replay --issue N` on the staged commit")
    return require_artifact(run.replay.output_path, run.replay.output_sha256, home, "replay")


def _certified_gates(run: Run) -> tuple:
    if run.green is not None and run.green.observations:
        return run.green.observations
    head = run.expected_green_sha or run.green_sha
    if run.red is None or head is None:
        raise UsageError("gate evidence cannot be selected without a staged commit and red identity")
    return tuple(
        observation
        for observation in run.gate_observations
        if observation.exit == 0
        and observation.head_sha == head
        and observation.gate_digest == run.gate_digest
        and observation.test_blob_sha256 == run.red.test.blob_sha256
    )


def require_gates(run: Run, home: Path) -> None:
    chosen = {observation.gate: observation for observation in _certified_gates(run)}
    if set(chosen) != set(GATES):
        raise PolicyError(f"green parity failed: passing gate evidence is incomplete ({sorted(chosen)})")
    for name in GATES:
        require_artifact(chosen[name].output_path, chosen[name].output_sha256, home, f"gate {name}")


OBSERVED = "observed-helper-execution"


def require_observed(run: Run) -> None:
    if run.red is None or run.replay is None:
        raise PolicyError("green needs observed red and replay evidence")
    for label, provenance in (("red", run.red.provenance), ("replay", run.replay.provenance)):
        if provenance != OBSERVED:
            raise PolicyError(
                f"{label} evidence provenance is {provenance!r}; only {OBSERVED} can produce green"
            )
    for observation in _certified_gates(run):
        if observation.provenance != OBSERVED:
            raise PolicyError(
                f"gate {observation.gate} evidence provenance is {observation.provenance!r}; "
                f"only {OBSERVED} can produce green"
            )


def require_all(run: Run, home: Path) -> None:
    require_observed(run)
    require_red(run, home)
    require_replay(run, home)
    require_gates(run, home)


def read_manifest(path_text: str, home: Path) -> dict:
    path = _require_regular(path_text, home)
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorruptState(f"corrupt manifest {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CorruptState(f"corrupt manifest {path}: expected a JSON object")
    return parsed


def _expected_run_fields(run: Run) -> dict[str, object]:
    raw = {
        "schema": 1,
        "issue": run.issue,
        "feature": run.feature,
        "kind": run.kind,
        "declared_model": run.declared_model,
        "model_attestation": run.model_attestation,
        "execution_profile": run.execution_profile,
        "profile_attestation": (
            None if run.profile_attestation is None else run.profile_attestation.to_dict()
        ),
        "verification_mode": run.verified_by,
        "branch": run.branch,
        "base_sha": run.base_sha,
        "base_branch": run.base_branch,
        "red_sha": run.red_sha,
        "green_sha": run.green_sha,
        "admitted_at": run.admitted_at,
        "gate_digest": run.gate_digest,
        "phase": "local-verified",
        "limits": run.limits.to_dict() if run.limits is not None else None,
        "counters": asdict(run.counters),
        "red": asdict(run.red) if run.red is not None else None,
        "stage": asdict(run.stage) if run.stage is not None else None,
        "replay": asdict(run.replay) if run.replay is not None else None,
        "green": asdict(run.green) if run.green is not None else None,
    }
    return json.loads(json.dumps(raw))


def _matches_position(value: object, position: dict[str, object]) -> bool:
    return isinstance(value, dict) and all(value.get(key) == position[key] for key in position)


def _validate_budget_snapshot(payload: dict, run: Run) -> None:
    """The manifest holds the admission snapshot twice; the current export may move after it is written."""
    admission = payload.get("budget")
    if admission != payload.get("budget_admission"):
        raise CorruptState("existing manifest budget snapshot disagrees with budget_admission")
    if admission is None:
        if run.budget is not None:
            raise CorruptState("existing manifest omits the recorded admission budget")
        return
    try:
        BudgetPosition.from_dict(admission)
    except CorruptState as exc:
        raise CorruptState(f"existing manifest budget snapshot is corrupt: {exc}") from exc
    if run.budget is None:
        return
    recorded = json.loads(json.dumps(asdict(run.budget)))
    if admission != recorded and not _matches_position(payload.get("budget_current"), recorded):
        raise CorruptState("existing manifest budget snapshot does not match the recorded run budget")


def validate_manifest(payload: dict, run: Run, required_artifacts: list[str]) -> None:
    for key, value in _expected_run_fields(run).items():
        if payload.get(key) != value:
            raise CorruptState(
                f"existing manifest {key} mismatch: recorded {payload.get(key)!r}, expected {value!r}"
            )
    _validate_budget_snapshot(payload, run)
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        raise CorruptState("existing manifest has no usable evidence list")
    missing = [path for path in required_artifacts if path not in evidence]
    if missing:
        raise CorruptState(f"existing manifest omits required evidence: {missing}")
