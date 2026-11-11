"""Explicit replay of the exact red command on the staged commit.

The red capture proves the test failed before the implementation. This step proves the same argv,
selector, and test blob pass now. It is one approved command that launches one child; green only
reads the recorded replay and never runs it.
"""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import replace

from factory import config as config_module, gitio, integrity, lifecycle, runner
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.gate_records import ReplayEvidence
from factory.limits import RED_TIMEOUT
from factory.model import Run
from factory.paths import RuntimePaths, write_evidence
from factory.store import require_run, save_run


def matches_red(run: Run, record: ReplayEvidence, *, passing: bool) -> bool:
    if run.red is None or run.expected_green_sha is None:
        return False
    if passing and record.exit != 0:
        return False
    return (
        record.provenance == integrity.OBSERVED
        and record.head_sha == run.expected_green_sha
        and record.gate_digest == run.gate_digest
        and record.test_blob_sha256 == run.red.test.blob_sha256
        and record.selector == run.red.test.selector
        and tuple(record.argv) == tuple(run.red.argv)
    )


def require_passing(run: Run) -> ReplayEvidence:
    if run.replay is None:
        raise PolicyError("no replay recorded; run `factory replay --issue N` on the staged commit")
    if not matches_red(run, run.replay, passing=True):
        raise PolicyError(
            "the recorded replay is not an observed passing replay of the exact red argv, selector, "
            "test blob, and gate digest on the staged commit"
        )
    return run.replay


def _require_staged(paths: RuntimePaths, run: Run) -> str:
    if run.red is None or run.expected_green_sha is None:
        raise UsageError("no red evidence or staged commit; run red and stage first")
    if gitio.status_porcelain(paths.repo, operator_repo=True):
        raise PolicyError("working tree is dirty; replay needs a clean tree")
    if gitio.branch(paths.repo) != run.branch:
        raise PolicyError(f"current branch is not {run.branch}")
    head = gitio.head(paths.repo)
    if head != run.expected_green_sha:
        raise PolicyError(f"HEAD {head} does not match the staged commit {run.expected_green_sha}")
    if head == run.red_sha:
        raise PolicyError("replay must run on a different commit than red")
    if not gitio.is_ancestor(paths.repo, run.red_sha or "", head):
        raise PolicyError("the staged commit does not descend from the recorded red commit")
    raw = gitio.file_at_head(paths.repo, run.red.test.file)
    if hashlib.sha256(raw).hexdigest() != run.red.test.blob_sha256:
        raise PolicyError("the red test changed since capture; replay cannot prove the same test")
    return head


def replay(paths: RuntimePaths, issue: int) -> ReplayEvidence:
    run = require_run(paths, issue)
    config_module.for_run(paths, run)
    if run.phase in ("green", "local-verified") and run.replay is not None and matches_red(run, run.replay, passing=True):
        integrity.require_replay(run, paths.home)
        print(f"replay already recorded at {run.replay.head_sha} (not re-executed)")
        return run.replay
    if run.phase != "gates":
        raise UsageError(f"issue {issue} is {run.phase}; replay needs a staged run")
    head = _require_staged(paths, run)
    if run.replay is not None and matches_red(run, run.replay, passing=True):
        integrity.require_replay(run, paths.home)
        print(f"replay already recorded at {head} (not re-executed)")
        return run.replay
    run = lifecycle.enforce_limits(paths, run)
    run = lifecycle.require_budget(paths, run)
    run = save_run(paths, replace(run, counters=replace(run.counters, operations_used=run.counters.operations_used + 1)))
    argv = run.red.argv
    print(f"replay: executing {shlex.join(argv)}")
    result = runner.execute(paths.repo, argv, lifecycle.child_timeout(run, RED_TIMEOUT))
    evidence_path = write_evidence(paths.issue_evidence(issue), f"replay-{head[:12]}", result.output, paths.home)
    record = ReplayEvidence(
        head_sha=head,
        argv=argv,
        selector=run.red.test.selector,
        exit=result.exit,
        output_sha256=runner.digest_text(result.output),
        output_path=str(evidence_path),
        at=now(),
        duration_ms=result.duration_ms,
        test_blob_sha256=run.red.test.blob_sha256,
        gate_digest=run.gate_digest,
        provenance="observed-helper-execution",
    )
    if result.exit != 0:
        save_run(paths, replace(run, replay=record))
        raise PolicyError(f"replay failed (exit {result.exit}); the red command is not green on this commit")
    lifecycle.verify_elapsed(paths, run)
    save_run(paths, replace(run, replay=record))
    print(f"replay recorded at {head} with exit 0 for {run.red.test.file} :: {run.red.test.selector}")
    return record
