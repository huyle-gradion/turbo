"""Command-line entry point for the private operator workflow."""

from __future__ import annotations

import argparse
import json
import sys

from factory import admission, budget, config as config_module, deliver as deliver_module, doctor, gates, intake as intake_module, lifecycle, store
from factory import green as green_module, manifest as manifest_module, redstage, replay as replay_module
from factory import profile as profile_module, verify as verify_module, worker as worker_module
from factory.args import build_parser
from factory.config import GateConfig
from factory.errors import PolicyError, UsageError
from factory.paths import RuntimePaths, ensure_home, resolve_paths
from factory.prompt import prompt
from factory.report import status_payload


def _configure_gate(paths: RuntimePaths, args: argparse.Namespace) -> int:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    name = args.gate
    if name is None:
        raise UsageError("configure needs --profile, --gate, or --timezone")
    argv = tuple(args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv)
    if name in ("1", "2"):
        if not argv or any(not item for item in argv):
            raise UsageError(f"gate {name} needs a non-empty argv after --")
        if not argv[0].strip():
            raise UsageError(f"gate {name} executable argv[0] must not be blank")
        declarations = [flag for flag, given in (
            (profile_module.HOST_DENIES_WRITES, args.declare_host_deny),
            (profile_module.HOST_POLICY_PROBED, args.declare_host_probed),
        ) if given]
        if name == "1":
            if len(declarations) != 1:
                raise UsageError(
                    "gate 1 needs exactly one operator declaration: --declare-host-deny or --declare-host-probed"
                )
            declaration = declarations[0]
            profile_module.require_host_declaration(conf.execution_profile, declaration)
        else:
            if declarations:
                raise UsageError("a host-policy declaration belongs to gate 1 only")
            declaration = profile_module.NOT_APPLICABLE
        label = args.label or (
            "protected host deny (operator-declared)" if name == "1" and declaration == profile_module.HOST_DENIES_WRITES
            else "host policy (operator-probed)" if name == "1"
            else "project checks"
        )
        if not 1 <= args.timeout <= config_module.MAX_TIMEOUT:
            raise UsageError(f"gate timeout must be 1..{config_module.MAX_TIMEOUT} seconds")
        gate = GateConfig(kind="command", label=label, argv=argv, timeout_seconds=args.timeout,
                          declaration=declaration)
    elif name == "3":
        if args.declare_host_deny or args.declare_host_probed:
            raise UsageError("a host-policy declaration belongs to gate 1 only")
        protected = tuple(args.protected)
        if not protected:
            raise UsageError("gate 3 needs at least one --protected path")
        for item in protected:
            issue = config_module.protected_entry_issue(item)
            if issue is not None:
                raise UsageError(f"protected path {item!r} {issue}")
        gate = GateConfig(kind="protected-paths", label=args.label or "protected-path invariance", paths=protected)
    else:
        raise UsageError(f"unknown gate: {name}")
    config_module.save(paths, config_module.with_gate(conf, name, gate))
    print(f"configured gate {name}: {gate.label}")
    return 0


def _configure_profile(paths: RuntimePaths, args: argparse.Namespace) -> int:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    if args.profile is None:
        raise UsageError("--attest-native-turbo needs --profile native-turbo")
    if args.profile == profile_module.MANUAL:
        if args.attest_native_turbo is not None:
            raise UsageError("the manual profile has no native Turbo attestation to record")
        updated = config_module.with_profile(conf, profile_module.MANUAL, None)
        config_module.save(paths, updated)
        print("configured execution profile: manual (one operator-approved command at a time)")
        return 0
    if args.attest_native_turbo is None:
        raise UsageError(
            "native-turbo needs --attest-native-turbo HOST; the helper cannot detect a host mode "
            "and this attestation is not a permission or sandbox proof"
        )
    attestation = profile_module.NativeTurboAttestation(
        host=args.attest_native_turbo.strip(),
        declared_at=config_module.now(),
    )
    updated = config_module.with_profile(conf, profile_module.NATIVE_TURBO, attestation)
    config_module.save(paths, updated)
    print(
        f"configured execution profile: native-turbo ({attestation.host}; operator-attested, host not verified)"
    )
    return 0


def _configure(paths: RuntimePaths, args: argparse.Namespace) -> int:
    profile_named = args.profile is not None or args.attest_native_turbo is not None
    if profile_named:
        if args.timezone or args.gate:
            raise UsageError("configure one thing per invocation: --profile, --gate, or --timezone")
        if args.declare_host_deny or args.declare_host_probed:
            raise UsageError("a host-policy declaration belongs to gate 1, not the profile")
        return _configure_profile(paths, args)
    if args.timezone and args.gate:
        raise UsageError("configure one thing per invocation: --gate or --timezone")
    if args.timezone:
        conf = config_module.load(paths)
        config_module.require_binding(conf, paths)
        config_module.save(paths, config_module.with_timezone(conf, args.timezone))
        print(f"configured budget timezone: {args.timezone}")
        return 0
    return _configure_gate(paths, args)


def _init(paths: RuntimePaths) -> int:
    if paths.config.exists():
        conf = config_module.load(paths)
        config_module.require_binding(conf, paths)
        ensure_home(paths)
        print(f"already initialized: {paths.config}")
        return 0
    ensure_home(paths)
    config_module.save(paths, config_module.skeleton(paths))
    print(f"initialized private home {paths.home} for {paths.repo}")
    return 0


def _status(paths: RuntimePaths, issue: int, as_json: bool) -> int:
    run = store.load_run(paths, issue)
    if run is None:
        raise UsageError(f"no run state for issue {issue}")
    payload = status_payload(run)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if run.budget is None or run.budget.state != "known":
        spend = "UNPRICED"
    else:
        spend = f"${run.budget.usd} ({run.budget.week}, operator-declared)"
    print(f"issue: {run.issue}")
    print(f"phase: {run.phase}")
    print(f"kind: {run.kind}")
    print(f"model: {run.declared_model} ({run.model_attestation})")
    print(f"execution_profile: {profile_module.describe(run.execution_profile, run.profile_attestation)}")
    print(f"verified_by: {run.verified_by}")
    print(f"stop_reason: {run.stop_reason or '-'}")
    if run.stop_detail:
        print(f"stop_detail: {run.stop_detail}")
    print(f"branch: {run.branch}")
    print(f"base_sha: {run.base_sha}")
    print(f"red_sha: {run.red_sha or '-'}")
    print(f"green_sha: {run.green_sha or '-'}")
    print(f"budget: {spend}")
    print(f"counters: operations={run.counters.operations_used} repairs={run.counters.repairs_used}/{run.counters.repair_cap}")
    if run.limits is not None:
        print(f"limits: time={run.limits.time_seconds}s operations={run.limits.operations} turns=supervision-only writes=supervision-only")
    print(f"gates: {','.join(run.gate_chain) or '-'}")
    print(f"evidence: {run.evidence_dir}")
    print(f"manifest: {run.manifest_path or '-'}")
    return 0


def _spend(paths: RuntimePaths, args: argparse.Namespace) -> int:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    if args.spend_action == "record":
        week = args.week or budget.week_key(conf.budget)
        usd = None if args.unknown else args.usd
        spend = budget.record(conf.budget, week, usd, args.source)
        config_module.save(paths, config_module.with_week(conf, week, spend))
        print(f"recorded {week}: {spend.state} {spend.usd} ({spend.verification})")
        return 0
    week, spend = budget.show(conf.budget, args.week)
    if spend is None or spend.state != "known":
        print(f"{week}: UNPRICED (no known declaration; unknown is not zero)")
        return 0
    print(f"{week}: known ${spend.usd} source={spend.source} ({spend.verification})")
    return 0


def _dispatch(paths: RuntimePaths, args: argparse.Namespace) -> int:
    match args.action:
        case "init":
            return _init(paths)
        case "configure":
            return _configure(paths, args)
        case "doctor":
            checks = doctor.diagnose(paths)
            if args.json:
                print(json.dumps([{"name": item.name, "ok": item.ok, "detail": item.detail} for item in checks], indent=2))
                return 0 if all(item.ok for item in checks) else 1
            return doctor.report(checks)
        case "status":
            return _status(paths, args.issue, args.json)
        case "spend":
            return _spend(paths, args)
        case "prepare":
            run = admission.prepare(paths, args)
            print(f"admitted issue {run.issue} at {run.base_sha} (local run record, not company approval); next: git switch -c {run.branch}")
            return 0
        case "red":
            redstage.red(paths, args.issue, test=args.test, selector=args.selector, command=args.command, expect=args.expect)
            return 0
        case "stage":
            redstage.stage(paths, args.issue, args.commit)
            return 0
        case "replay":
            replay_module.replay(paths, args.issue)
            return 0
        case "gate":
            gates.execute(paths, args.issue, args.gate)
            return 0
        case "green":
            green_module.green(paths, args.issue)
            return 0
        case "verify":
            verify_module.verify(paths, args.issue)
            return 0
        case "manifest":
            manifest_module.manifest(paths, args.issue)
            return 0
        case "prompt":
            run = store.require_run(paths, args.issue)
            print(prompt(run))
            return 0
        case "stop":
            run = lifecycle.stop(paths, args.issue, args.reason, args.detail)
            print(f"issue {run.issue}: {run.phase} ({run.stop_reason})")
            return 0
        case "resume":
            entry = lifecycle.resume(paths, args.issue, args.pr)
            if entry.verdict == "consistent":
                print(f"resume consistent: {entry.branch} @ {entry.head_sha}")
                return 0
            print(f"resume refused: {', '.join(entry.reasons)}")
            return 1
        case "worker":
            result = worker_module.run_from_cli(paths, args)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            else:
                print(f"worker {result.task_id}: {result.status} ({result.artifact['relative_path']})")
            return 0 if result.completed else 1
        case "intake":
            result = intake_module.run_from_cli(paths, args)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            else:
                print(f"intake {result.task_gid}: {result.status} (delivery_ready={result.delivery_ready})")
            return 0 if result.delivery_ready else 1
        case "deliver":
            result = deliver_module.run_from_cli(paths, args)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            else:
                print(f"deliver {result.task_gid}: {result.status} (pr_opened={result.pr_opened})")
            return 0 if result.pr_opened else 1
        case unreachable:
            raise AssertionError(unreachable)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = resolve_paths(args.repo, args.home)
        return _dispatch(paths, args)
    except PolicyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"filesystem error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BROAD_EXCEPT_OK - CLI boundary, no traceback
        print(f"internal error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
