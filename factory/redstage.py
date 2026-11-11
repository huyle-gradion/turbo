"""Red capture and the staged expected commit."""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import replace
from pathlib import Path

from factory import config as config_module, gitio, lifecycle, runner
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.limits import RED_TIMEOUT
from factory.model import RedEvidence, StageContract, TestIdentity
from factory.paths import RuntimePaths, write_evidence
from factory.store import require_run, save_run


def _test_identity(repo: Path, raw: str, selector: str, command: str, protected: tuple[str, ...]) -> TestIdentity:
    if not raw.strip() or not selector.strip() or not command.strip():
        raise UsageError("test path, selector, and command are required")
    candidate = Path(raw)
    if candidate.is_absolute():
        raise UsageError("the test path must be relative to the repository")
    resolved = (repo / candidate).resolve()
    if not resolved.is_relative_to(repo):
        raise UsageError(f"the test path escapes the repository: {raw}")
    if not resolved.is_file():
        raise UsageError(f"the test file does not exist: {raw}")
    relative = resolved.relative_to(repo).as_posix()
    if config_module.protected_match(relative, protected):
        raise UsageError(f"{relative} is a protected path and cannot be the red test")
    working = hashlib.sha256(resolved.read_bytes()).hexdigest()
    committed = hashlib.sha256(gitio.file_at_head(repo, relative)).hexdigest()
    if working != committed:
        raise UsageError(f"{relative} is not committed exactly at HEAD")
    return TestIdentity(file=relative, selector=selector, command=command, blob_sha256=working)


def red(paths: RuntimePaths, issue: int, *, test: str, selector: str, command: str, expect: str) -> RedEvidence:
    run = require_run(paths, issue)
    conf = config_module.for_run(paths, run)
    if run.phase != "ready":
        raise UsageError(f"issue {issue} is {run.phase}; red needs a ready run")
    if not expect:
        raise UsageError("red needs an explicit --expect marker")
    run = lifecycle.enforce_limits(paths, run)
    run = lifecycle.require_budget(paths, run)
    gitio.require_clean(paths.repo, operator_repo=True)
    if gitio.branch(paths.repo) != run.branch:
        raise UsageError(f"current branch is not {run.branch}")
    head = gitio.head(paths.repo)
    if not gitio.is_ancestor(paths.repo, run.base_sha, head):
        raise UsageError("HEAD is not a descendant of the admitted base commit")
    protected = conf.gates["3"].paths if "3" in conf.gates else ()
    identity = _test_identity(paths.repo, test, selector, command, protected)
    try:
        argv = tuple(shlex.split(command))
    except ValueError as exc:
        raise UsageError(f"invalid red command: {exc}") from exc
    if not argv:
        raise UsageError("red command is empty")
    run = save_run(paths, replace(run, counters=replace(run.counters, operations_used=run.counters.operations_used + 1)))
    print(f"red: executing {shlex.join(argv)}")
    result = runner.execute(paths.repo, argv, lifecycle.child_timeout(run, RED_TIMEOUT))
    evidence_path = write_evidence(paths.issue_evidence(issue), f"red-{head[:12]}", result.output, paths.home)
    evidence = RedEvidence(
        test=identity,
        command=command,
        argv=argv,
        expect=expect,
        exit=result.exit,
        output_sha256=runner.digest_text(result.output),
        output_path=str(evidence_path),
        at=now(),
        head_sha=head,
        provenance="observed-helper-execution",
    )
    if result.exit == 0:
        lifecycle.stop_with(paths, run, "not-ready", "red command passed; there is no failing behavior")
        raise PolicyError(f"red refused: the command passed (exit 0); expected failure marker {expect!r}")
    if expect not in result.output:
        lifecycle.stop_with(paths, run, "not-ready", f"red failed for an unexpected reason; marker {expect!r} absent")
        raise PolicyError(f"red refused: marker {expect!r} absent from the failing output")
    lifecycle.verify_elapsed(paths, run)
    run = save_run(paths, replace(run, phase="red", red_sha=head, red=evidence, stop_reason=None, stop_detail=None))
    print(f"red recorded at {head} for {identity.file} :: {identity.selector} (exit {result.exit})")
    return evidence


def stage(paths: RuntimePaths, issue: int, commit: str) -> StageContract:
    run = require_run(paths, issue)
    config_module.for_run(paths, run)
    if run.phase not in ("red", "gates"):
        raise UsageError(f"issue {issue} is {run.phase}; stage needs red evidence")
    if run.red is None or run.red_sha is None:
        raise UsageError("no red evidence; run red first")
    gitio.require_clean(paths.repo, operator_repo=True)
    if gitio.branch(paths.repo) != run.branch:
        raise UsageError(f"current branch is not {run.branch}")
    head = gitio.head(paths.repo)
    canonical = gitio.commit_sha(paths.repo, commit)
    if canonical != head:
        raise UsageError(f"--commit {commit} does not match HEAD {head}")
    if head == run.red_sha:
        raise PolicyError("green must be a different commit than red")
    if not gitio.is_ancestor(paths.repo, run.red_sha, head):
        raise PolicyError("the staged commit does not descend from the recorded red commit; rewritten history discards the red evidence")
    if not gitio.is_ancestor(paths.repo, run.base_sha, head):
        raise UsageError("the staged commit is not a descendant of the admitted base")
    raw = gitio.file_at_head(paths.repo, run.red.test.file)
    if hashlib.sha256(raw).hexdigest() != run.red.test.blob_sha256:
        raise UsageError("the red test changed since capture; re-run red before staging")
    run = lifecycle.enforce_limits(paths, run)
    run = lifecycle.require_budget(paths, run)
    contract = StageContract(
        expected_head=head,
        red_sha=run.red_sha,
        test_blob_sha256=run.red.test.blob_sha256,
        recorded_at=now(),
    )
    save_run(
        paths,
        replace(
            run,
            phase="gates",
            expected_green_sha=head,
            stage=contract,
            replay=None,
            gate_chain=(),
            green=None,
            stop_reason=None,
            stop_detail=None,
        ),
    )
    print(f"staged expected green commit {head}")
    return contract
