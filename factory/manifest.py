"""Private evidence manifest. Written once, then revalidated, never overwritten."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, replace
from pathlib import Path

from factory import budget as budget_module, config as config_module, integrity
from factory import profile as profile_module
from factory import replay as replay_module
from factory.config import Config, now
from factory.errors import PolicyError, UsageError
from factory.model import BudgetPosition, Run
from factory.paths import RuntimePaths, safe_dir
from factory.store import require_run, save_run


def _current_budget(conf: Config, run: Run) -> tuple[dict[str, object], BudgetPosition | None]:
    try:
        current = budget_module.position(conf.budget)
    except PolicyError as exc:
        return (
            {
                "week": None,
                "state": "unknown",
                "usd": None,
                "admissible": False,
                "refusal": str(exc),
                "verification": "operator-declared; not independently verified",
            },
            None,
        )
    reason = budget_module.violation(conf.budget, run.kind, current)
    return {**asdict(current), "admissible": reason is None, "refusal": reason}, current


def _required_paths(run: Run) -> list[str]:
    if run.red is None or run.replay is None:
        raise UsageError("manifest refused: red or replay evidence is missing")
    paths = [run.red.output_path, run.replay.output_path]
    if run.green is None:
        raise UsageError("manifest refused: green evidence is missing")
    return paths + [item.output_path for item in run.green.observations]


def _exclusive_write(target: Path, text: str) -> None:
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(target, 0o600)


def _write_manifest(paths: RuntimePaths, issue: int, payload: dict[str, object]) -> Path:
    directory = safe_dir(paths.issue_evidence(issue), create=True, root=paths.home)
    target = directory / "manifest.json"
    if target.is_symlink() or target.exists():
        return target
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(dir=directory, prefix=".manifest.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, target)
        except FileExistsError:
            return target
        except OSError:
            # Filesystems without hard links fall back to an exclusive create of the full text.
            # A crash mid-write leaves a partial file, which the read-back validation below refuses.
            _exclusive_write(target, text)
        return target
    finally:
        if temporary.exists():
            temporary.unlink()


def manifest(paths: RuntimePaths, issue: int) -> Path:
    run = require_run(paths, issue)
    if run.phase not in ("green", "local-verified"):
        raise UsageError(f"issue {issue} is {run.phase}; manifest needs green evidence")
    conf = config_module.for_run(paths, run)
    required = _required_paths(run)
    replay_module.require_passing(run)
    integrity.require_all(run, paths.home)
    if run.manifest_path:
        payload = integrity.read_manifest(run.manifest_path, paths.home)
        integrity.validate_manifest(payload, run, required)
        print(f"manifest already exists at {run.manifest_path} (revalidated, not overwritten)")
        return Path(run.manifest_path)
    admission = asdict(run.budget) if run.budget is not None else None
    current, refreshed = _current_budget(conf, run)
    payload = {
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
        "gate_config": {name: gate.to_dict() for name, gate in sorted(conf.gates.items())},
        "budget": admission,
        "budget_admission": admission,
        "budget_current": current,
        "limits": run.limits.to_dict() if run.limits is not None else None,
        "counters": asdict(run.counters),
        "red": asdict(run.red),
        "stage": asdict(run.stage) if run.stage is not None else None,
        "replay": asdict(run.replay),
        "green": asdict(run.green),
        "evidence": required,
        "phase": "local-verified",
        "approval": "not an independent QC approval; no company permission",
        "provenance": {
            "red": run.red.provenance,
            "replay": run.replay.provenance,
            "gates": sorted({item.provenance for item in run.green.observations}),
            "gate_1_host_deny": (
                "not claimed; native Turbo records an operator-probed host policy"
                if run.execution_profile == profile_module.NATIVE_TURBO
                else "operator-declared; not validated"
            ),
            "gate_1_declaration": conf.gates["1"].declaration,
            "execution_profile": "operator-attested; the helper never detects or changes host permissions",
            "verification_mode": run.verified_by,
            "model_account": "operator-declared; not observed",
            "spend": "operator-declared; not independently verified; admission and current positions are separate fields",
            "green": run.green.provenance,
            "test_identity": "file and blob observed at HEAD; selector and command are operator-supplied labels",
            "red_marker": f"operator-declared expectation {run.red.expect!r}; the helper checked that substring only",
            "capture_ingest": "not used; child facts come from direct helper execution",
            "artifacts": "red, replay, and gate files are re-hashed from the private home before green and manifest",
        },
        "notes": {
            "gate_one": "operator-declared host policy; the factory observed only the command exit",
            "execution_profile": "manual or native-turbo is an operator declaration, not a permission grant",
            "gate_three": "compares base..HEAD with NUL-separated paths; the gate precondition refuses a dirty tree first",
            "cost": "spend is operator-declared and not independently verified; unpriced stays unknown",
            "state": "operator-owned files outside the product repository; gate digest detects accidental drift only",
        },
        "generated_at": now(),
    }
    target = _write_manifest(paths, issue, payload)
    written = integrity.read_manifest(str(target), paths.home)
    integrity.validate_manifest(written, run, required)
    updated = run if refreshed is None else replace(run, budget=refreshed)
    save_run(paths, replace(updated, phase="local-verified", manifest_path=str(target)))
    print(f"manifest written to {target}")
    return target
