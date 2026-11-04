"""Green verification. It reads recorded proof and never launches a command."""

from __future__ import annotations

import hashlib
from dataclasses import replace

from factory import config as config_module, gitio, integrity, lifecycle
from factory import replay as replay_module
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.gate_records import GateObservation, GreenEvidence
from factory.model import Run
from factory.paths import RuntimePaths
from factory.store import require_run, save_run

GATES = ("1", "2", "3")


def _require_current(paths: RuntimePaths, run: Run) -> str:
    if gitio.status_porcelain(paths.repo):
        raise PolicyError("working tree is dirty; green needs a clean tree")
    if gitio.branch(paths.repo) != run.branch:
        raise PolicyError(f"current branch is not {run.branch}")
    head = gitio.head(paths.repo)
    expected = run.green_sha or run.expected_green_sha
    if head != expected:
        raise PolicyError(f"HEAD {head} does not match the recorded commit {expected}")
    return head


def _selected_gates(run: Run, head: str) -> dict[str, GateObservation]:
    if run.red is None:
        return {}
    by_gate: dict[str, GateObservation] = {}
    for observation in run.gate_observations:
        if (
            observation.exit == 0
            and observation.head_sha == head
            and observation.gate_digest == run.gate_digest
            and observation.test_blob_sha256 == run.red.test.blob_sha256
        ):
            by_gate[observation.gate] = observation
    return by_gate


def green(paths: RuntimePaths, issue: int) -> GreenEvidence:
    run = require_run(paths, issue)
    config_module.for_run(paths, run)
    if run.red is None or run.expected_green_sha is None:
        raise UsageError("no red or staged commit; run red and stage first")
    if run.phase not in ("gates", "green", "local-verified"):
        raise UsageError(f"issue {issue} is {run.phase}; green needs a staged run")
    head = _require_current(paths, run)
    raw = gitio.file_at_head(paths.repo, run.red.test.file)
    if hashlib.sha256(raw).hexdigest() != run.red.test.blob_sha256:
        raise PolicyError("the red test changed since capture; green parity failed")
    if run.phase in ("green", "local-verified") and run.green is not None:
        replay_module.require_passing(run)
        integrity.require_all(run, paths.home)
        print(f"green already recorded at {run.green.head_sha}; HEAD and raw artifacts revalidated (not overwritten)")
        return run.green
    if not gitio.is_ancestor(paths.repo, run.red_sha or "", head):
        raise PolicyError("the staged commit does not descend from the recorded red commit")
    if run.gate_chain != GATES:
        raise PolicyError(f"gate chain incomplete: {list(run.gate_chain)}; run the gates individually")
    by_gate = _selected_gates(run, head)
    if set(by_gate) != set(GATES):
        raise PolicyError("green parity failed: the passing gate evidence is not for this commit")
    replay_module.require_passing(run)
    integrity.require_all(run, paths.home)
    lifecycle.verify_elapsed(paths, run)
    run = lifecycle.require_budget(paths, run)
    evidence = GreenEvidence(
        head_sha=head,
        test_blob_sha256=run.red.test.blob_sha256,
        gate_digest=run.gate_digest,
        at=now(),
        observations=(by_gate["1"], by_gate["2"], by_gate["3"]),
        provenance="local-verified; not independent QC approval",
    )
    save_run(paths, replace(run, phase="green", green_sha=head, green=evidence))
    print(f"green recorded at {head} with gates 1, 2, 3 and one replay (evidence only)")
    return evidence
