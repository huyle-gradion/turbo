"""Configuration and state diagnosis without touching the product tree."""

from __future__ import annotations

from dataclasses import dataclass

from factory import config as config_module, gitio
from factory import profile as profile_module
from factory.errors import FactoryError
from factory.paths import FILE_MODE, HOME_MODE, RuntimePaths, safe_dir
from factory.store import load_run, run_issues


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def _check_home(paths: RuntimePaths) -> list[Check]:
    if not paths.home.exists():
        return [Check("home", False, f"missing: {paths.home}")]
    if paths.home.is_symlink():
        return [Check("home", False, "is a symlink")]
    mode = paths.home.stat().st_mode & 0o777
    return [Check("home", True, str(paths.home)), Check("home mode", mode == HOME_MODE, f"{oct(mode)} (expected {oct(HOME_MODE)})")]


def _check_config(paths: RuntimePaths) -> tuple[list[Check], config_module.Config | None]:
    try:
        conf = config_module.load(paths)
    except FactoryError as exc:
        return [Check("config", False, str(exc))], None
    checks = [Check("config", True, str(paths.config))]
    mode = paths.config.stat().st_mode & 0o777
    checks.append(Check("config mode", mode == FILE_MODE, f"{oct(mode)} (expected {oct(FILE_MODE)})"))
    try:
        config_module.require_binding(conf, paths)
        checks.append(Check("binding", True, f"{conf.repo} -> {conf.home}"))
    except FactoryError as exc:
        checks.append(Check("binding", False, str(exc)))
    issues = config_module.completeness_issues(conf)
    checks.append(Check("gates", not issues, "; ".join(issues) if issues else "1, 2, 3 configured"))
    checks.append(
        Check(
            "execution profile",
            conf.execution_profile == profile_module.MANUAL or conf.native_turbo_attestation is not None,
            profile_module.describe(conf.execution_profile, conf.native_turbo_attestation),
        )
    )
    one = conf.gates.get("1")
    declaration = None if one is None else one.declaration
    if one is None:
        checks.append(Check("gate 1 declaration", False, "missing gate 1"))
    elif conf.execution_profile == profile_module.NATIVE_TURBO:
        probed = declaration == profile_module.HOST_POLICY_PROBED
        checks.append(
            Check(
                "gate 1 declaration",
                probed,
                "operator-probed host policy; the helper cannot validate a sandbox or write denial"
                if probed else "native-turbo needs --declare-host-probed for gate 1",
            )
        )
    else:
        declared = declaration in (profile_module.HOST_DENIES_WRITES, profile_module.HOST_POLICY_PROBED)
        checks.append(
            Check(
                "gate 1 declaration",
                declared,
                "operator-declared; the factory cannot validate it" if declared else "missing gate 1 declaration",
            )
        )
    return checks, conf


def _check_runs(paths: RuntimePaths, conf: config_module.Config | None) -> list[Check]:
    checks: list[Check] = []
    try:
        issues = run_issues(paths)
    except FactoryError as exc:
        return [Check("runs", False, str(exc))]
    checks.append(Check("runs", True, f"{len(issues)} stored"))
    if conf is None:
        return checks
    digest = config_module.digest(conf)
    for issue in issues:
        try:
            run = load_run(paths, issue)
        except FactoryError as exc:
            checks.append(Check(f"run {issue}", False, str(exc)))
            continue
        state_path = paths.run(issue)
        mode = state_path.stat().st_mode & 0o777
        checks.append(Check(f"run {issue} mode", mode == FILE_MODE, f"{oct(mode)} (expected {oct(FILE_MODE)})"))
        try:
            safe_dir(paths.issue_evidence(issue), create=False, root=paths.home)
        except FactoryError as exc:
            checks.append(Check(f"run {issue} evidence", False, str(exc)))
        if run is not None and run.gate_digest != digest:
            checks.append(Check(f"run {issue} digest", False, "gate configuration changed (digest mismatch)"))
        elif run is not None and (
            run.execution_profile != conf.execution_profile
            or run.profile_attestation != conf.native_turbo_attestation
        ):
            checks.append(Check(f"run {issue} profile", False, "execution profile changed since admission"))
    return checks


def diagnose(paths: RuntimePaths) -> list[Check]:
    checks = _check_home(paths)
    config_checks, conf = _check_config(paths)
    checks.extend(config_checks)
    try:
        checks.append(Check("repository", True, str(gitio.require_repo_root(paths.repo))))
    except FactoryError as exc:
        checks.append(Check("repository", False, str(exc)))
    checks.extend(_check_runs(paths, conf))
    return checks


def report(checks: list[Check]) -> int:
    for check in checks:
        marker = "PASS" if check.ok else "FAIL"
        print(f"{marker} {check.name}: {check.detail}")
    return 0 if all(check.ok for check in checks) else 1
