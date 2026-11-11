"""One gate per invocation. The ladder is never run behind a single command."""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import replace
from pathlib import Path

from factory import config as config_module, gitio, lifecycle, runner
from factory.config import GateConfig, now
from factory.errors import PolicyError, UsageError
from factory.gate_records import GateAttempt, GateObservation
from factory.model import Run
from factory.paths import RuntimePaths, write_evidence
from factory.store import require_run, save_run


def protected_changes(repo: Path, run: Run, protected: tuple[str, ...]) -> tuple[str, ...]:
    head = run.expected_green_sha or run.green_sha or gitio.head(repo)
    changed = set(gitio.changed_paths(repo, run.base_sha, head))
    changed.update(gitio.dirty_paths(repo, operator_repo=True))
    return tuple(sorted(path for path in changed if config_module.protected_match(path, protected)))


def _protected_result(repo: Path, run: Run, gate: GateConfig) -> tuple[int, str]:
    hits = protected_changes(repo, run, gate.paths)
    if not hits:
        return 0, "no protected path changed\n"
    return 1, "protected path changed:\n" + "\n".join(hits) + "\n"


def _require_inputs(paths: RuntimePaths, run: Run, name: str) -> config_module.Config:
    conf = config_module.for_run(paths, run)
    if run.phase != "gates":
        raise UsageError(f"issue {run.issue} is {run.phase}; gates need a staged run")
    if run.expected_green_sha is None:
        raise UsageError("no staged expected commit; run stage first")
    if gitio.head(paths.repo) != run.expected_green_sha:
        raise UsageError("HEAD does not match the staged expected commit; re-stage before gating")
    if gitio.branch(paths.repo) != run.branch:
        raise UsageError(f"current branch is not {run.branch}")
    gitio.require_clean(paths.repo, operator_repo=True)
    if run.red is None:
        raise UsageError("no red evidence")
    raw = gitio.file_at_head(paths.repo, run.red.test.file)
    if hashlib.sha256(raw).hexdigest() != run.red.test.blob_sha256:
        raise UsageError("the red test changed since capture; re-run red before gating")
    if not gitio.is_ancestor(paths.repo, run.red_sha or "", run.expected_green_sha):
        raise UsageError("the staged commit does not descend from the recorded red commit; re-run red and stage")
    gate = conf.gates.get(name)
    if gate is None:
        raise UsageError(f"gate {name} is not configured")
    return conf


def execute(paths: RuntimePaths, issue: int, name: str) -> GateObservation:
    config_module.load(paths)
    run = require_run(paths, issue)
    conf = _require_inputs(paths, run, name)
    run = lifecycle.enforce_limits(paths, run)
    run = lifecycle.require_budget(paths, run)
    gate = conf.gates[name]
    if name == "2" and run.gate_chain != ("1",):
        raise UsageError("gate 2 needs a passing gate 1 for this staged commit")
    if name == "3" and run.gate_chain != ("1", "2"):
        raise UsageError("gate 3 needs passing gates 1 and 2 for this staged commit")
    if name == "1":
        run = replace(run, gate_chain=())
    run = save_run(paths, replace(run, counters=replace(run.counters, operations_used=run.counters.operations_used + 1)))

    if gate.kind == "command":
        print(f"gate {name}: executing {shlex.join(gate.argv)}")
        result = runner.execute(paths.repo, gate.argv, lifecycle.child_timeout(run, gate.timeout_seconds))
        output, exit_code, argv, duration = result.output, result.exit, result.argv, result.duration_ms
    else:
        print(f"gate {name}: checking protected paths {' '.join(gate.paths)}")
        exit_code, output = _protected_result(paths.repo, run, gate)
        argv, duration = (), 0
    stem = f"gate-{name}-{(run.expected_green_sha or 'none')[:12]}"
    evidence_path = write_evidence(paths.issue_evidence(issue), stem, output, paths.home)
    observation = GateObservation(
        gate=name,
        kind=gate.kind,
        argv=argv,
        exit=exit_code,
        output_sha256=hashlib.sha256(output.encode("utf-8")).hexdigest(),
        output_path=str(evidence_path),
        at=now(),
        duration_ms=duration,
        head_sha=run.expected_green_sha or "",
        test_blob_sha256=run.red.test.blob_sha256 if run.red else "",
        gate_digest=run.gate_digest,
        provenance="observed-helper-execution",
    )
    observations = (*run.gate_observations, observation)
    if exit_code == 0:
        lifecycle.verify_elapsed(paths, run)
        save_run(paths, replace(run, gate_chain=(*run.gate_chain, name), gate_observations=observations))
        shown = " ".join(argv) if argv else "protected-path invariant"
        print(f"gate {name} passed in {duration}ms (observed exit, not company approval): {shown}")
        return observation

    attempts = (
        *run.gate_attempts,
        GateAttempt(gate=name, at=now(), reason=f"exit {exit_code}", head_sha=run.expected_green_sha or ""),
    )
    counters = replace(run.counters, repairs_used=run.counters.repairs_used + 1)
    failed = replace(run, gate_chain=(), gate_attempts=attempts, gate_observations=observations, counters=counters)
    if counters.repairs_used > counters.repair_cap:
        lifecycle.stop_with(paths, failed, "retry-cap", f"repair cap {counters.repair_cap} exceeded")
        raise PolicyError(f"gate {name} failed (exit {exit_code}); repair cap exceeded, run stopped")
    save_run(paths, failed)
    raise PolicyError(f"gate {name} failed (exit {exit_code}); repairs {counters.repairs_used}/{counters.repair_cap}")
