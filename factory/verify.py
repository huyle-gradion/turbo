"""One explicit ordered verification bundle for the native Turbo profile.

This is the only command that launches several child processes from one invocation. It exists
because the operator selected the host's native unrestricted mode; it is not a mode switch, an
approval bypass, or a sandbox proof. Manual runs keep their one-command-at-a-time surface.
"""

from __future__ import annotations

import shlex
from dataclasses import replace

from factory import budget as budget_module
from factory import config as config_module, gates, green as green_module, integrity, lifecycle
from factory import manifest as manifest_module, profile as profile_module, replay as replay_module
from factory.errors import CorruptState, PolicyError, UsageError
from factory.gate_records import GateObservation
from factory.model import Run
from factory.paths import RuntimePaths
from factory.store import require_run, save_run

GATES = ("1", "2", "3")
PREFIXES = ((), ("1",), ("1", "2"), ("1", "2", "3"))


def _require_profile(paths: RuntimePaths, run: Run) -> config_module.Config:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    if conf.execution_profile != profile_module.NATIVE_TURBO:
        raise PolicyError(
            "verify needs the native-turbo execution profile; manual mode runs one "
            "operator-approved command at a time"
        )
    config_module.require_complete(conf)
    if run.execution_profile != conf.execution_profile:
        raise PolicyError(
            "execution profile changed since admission: "
            f"{run.execution_profile} -> {conf.execution_profile}; the admitted policy cannot be muted"
        )
    if run.profile_attestation != conf.native_turbo_attestation:
        raise PolicyError("native Turbo attestation changed since admission; the run cannot continue")
    if config_module.digest(conf) != run.gate_digest:
        raise PolicyError(
            "gate or budget policy configuration changed since admission (digest mismatch); reconcile it first"
        )
    return conf


def _matching_observation(run: Run, name: str) -> GateObservation | None:
    if run.red is None or run.expected_green_sha is None:
        return None
    for observation in reversed(run.gate_observations):
        if (
            observation.gate == name
            and observation.exit == 0
            and observation.head_sha == run.expected_green_sha
            and observation.gate_digest == run.gate_digest
            and observation.test_blob_sha256 == run.red.test.blob_sha256
            and observation.provenance == integrity.OBSERVED
        ):
            return observation
    return None


def _pending_gates(paths: RuntimePaths, run: Run) -> tuple[str, ...]:
    chain = tuple(run.gate_chain)
    if chain not in PREFIXES:
        raise PolicyError(f"gate chain is not an ordered prefix: {list(chain)}; re-stage and rerun gate 1")
    for name in chain:
        observation = _matching_observation(run, name)
        if observation is None:
            raise PolicyError(
                f"gate {name} is recorded as passed but has no matching observation for this commit and profile"
            )
        integrity.require_artifact(observation.output_path, observation.output_sha256, paths.home, f"gate {name}")
    return tuple(name for name in GATES if name not in chain)


def _replay_pending(paths: RuntimePaths, run: Run) -> bool:
    if run.replay is None:
        return True
    if not replay_module.matches_red(run, run.replay, passing=True):
        return True
    integrity.require_replay(run, paths.home)
    return False


def _print_plan(conf: config_module.Config, run: Run, pending: tuple[str, ...], replay: bool) -> None:
    used = run.counters.operations_used
    limit = run.limits.operations if run.limits is not None else "unknown"
    print(
        f"verify: issue {run.issue}, execution profile native-turbo "
        f"({run.profile_attestation.host if run.profile_attestation else 'unattested'})"
    )
    print(f"verify: operations {used}/{limit}; planned child operations {len(pending) + (1 if replay else 0)}")
    for name in pending:
        gate = conf.gates[name]
        if gate.kind == "command":
            print(f"verify: planned gate {name}: {shlex.join(gate.argv)}")
        else:
            print(f"verify: planned gate {name}: protected paths {' '.join(gate.paths)}")
    if replay and run.red is not None:
        print(f"verify: planned replay: {shlex.join(run.red.argv)}")
    print("verify: green and manifest read recorded evidence and launch no child")


def _mark_verified(paths: RuntimePaths, issue: int) -> None:
    run = require_run(paths, issue)
    if run.verified_by != profile_module.VERIFIED_BY_VERIFY:
        save_run(paths, replace(run, verified_by=profile_module.VERIFIED_BY_VERIFY))


def _zero_child(paths: RuntimePaths, run: Run) -> None:
    lifecycle.verify_elapsed(paths, run)
    lifecycle.require_budget(paths, run)
    green_module.green(paths, run.issue)
    manifest_module.manifest(paths, run.issue)


def _completed_reverify(paths: RuntimePaths, run: Run, conf: config_module.Config) -> None:
    """Revalidate the completed snapshot read-only: live budget, recorded evidence, existing manifest."""
    budget_module.attestation(conf.budget, run.kind)
    if not run.manifest_path:
        raise CorruptState(f"issue {run.issue} is local-verified but records no manifest")
    green_module.green(paths, run.issue)
    manifest_module.manifest(paths, run.issue)


def verify(paths: RuntimePaths, issue: int) -> None:
    run = require_run(paths, issue)
    conf = _require_profile(paths, run)
    if run.phase == "stopped":
        raise PolicyError(
            f"issue {issue} is stopped ({run.stop_reason}); resume it or start a new run before verifying"
        )
    if run.phase == "green":
        _zero_child(paths, run)
        state = require_run(paths, issue)
        print(f"verify: revalidated {state.phase} at {state.green_sha} without a child")
        return
    if run.phase == "local-verified":
        _completed_reverify(paths, run, conf)
        print(f"verify: revalidated {run.phase} at {run.green_sha} without a child or state change")
        return
    if run.phase != "gates":
        raise UsageError(f"issue {issue} is {run.phase}; verify needs a staged run")

    run = lifecycle.verify_elapsed(paths, run)
    run = lifecycle.require_budget(paths, run)
    pending = _pending_gates(paths, run)
    replay = _replay_pending(paths, run)

    needed = len(pending) + (1 if replay else 0)
    if run.limits is None or run.admitted_at is None:
        raise UsageError("run has no admitted operation limit")
    used = run.counters.operations_used
    if used + needed > run.limits.operations:
        raise PolicyError(
            f"operation budget insufficient for the ordered bundle: used {used}, need {needed} more "
            f"child operations, limit {run.limits.operations}; refused before any child"
        )

    _print_plan(conf, run, pending, replay)
    for name in pending:
        gates.execute(paths, issue, name)
    if replay:
        replay_module.replay(paths, issue)
    green_module.green(paths, issue)
    _mark_verified(paths, issue)
    manifest_module.manifest(paths, issue)
    state = require_run(paths, issue)
    print(
        f"verify complete: issue {issue} {state.phase} at {state.green_sha}; "
        "native-turbo profile recorded, local evidence only"
    )
