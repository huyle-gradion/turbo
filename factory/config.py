"""Operator-owned gate and budget configuration. Missing gates fail closed."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from factory import profile as profile_module
from factory.budgetpolicy import BudgetPolicy, WeekSpend
from factory.errors import CorruptState, UsageError
from factory.paths import RuntimePaths, atomic_json, read_json, safe_dir

SCHEMA = 1
DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 900
GATE_NAMES = ("1", "2", "3")


@dataclass(frozen=True, slots=True)
class GateConfig:
    kind: str
    label: str
    argv: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    timeout_seconds: int = DEFAULT_TIMEOUT
    declaration: str = profile_module.NOT_APPLICABLE

    def __post_init__(self) -> None:
        if self.declaration not in profile_module.DECLARATIONS:
            raise CorruptState(f"gate declaration invalid: {self.declaration!r}")

    @property
    def declare_host_deny(self) -> bool:
        return self.declaration == profile_module.HOST_DENIES_WRITES

    @classmethod
    def from_dict(cls, data: Any) -> GateConfig:
        if not isinstance(data, dict):
            raise CorruptState("gate must be an object")
        kind = data.get("kind")
        if kind not in ("command", "protected-paths"):
            raise CorruptState(f"gate kind invalid: {kind!r}")
        argv = data.get("argv", [])
        paths = data.get("paths", [])
        if not isinstance(argv, list) or not all(isinstance(item, str) and item for item in argv):
            raise CorruptState("gate argv must be a list of non-empty strings")
        if argv and not argv[0].strip():
            raise CorruptState("gate argv[0] must not be blank")
        if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
            raise CorruptState("gate paths must be a list of strings")
        for item in paths:
            issue = protected_entry_issue(item)
            if issue is not None:
                raise CorruptState(f"gate path {item!r} {issue}")
        timeout = data.get("timeout_seconds", DEFAULT_TIMEOUT)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
            raise CorruptState("gate timeout must be 1..900 seconds")
        raw_declaration = data.get("declaration")
        if raw_declaration is None:
            legacy = data.get("declare_host_deny", False)
            if not isinstance(legacy, bool):
                raise CorruptState("declare_host_deny must be a boolean")
            raw_declaration = profile_module.HOST_DENIES_WRITES if legacy else profile_module.NOT_APPLICABLE
        if raw_declaration not in profile_module.DECLARATIONS:
            raise CorruptState(f"gate declaration invalid: {raw_declaration!r}")
        return cls(
            kind=str(kind),
            label=str(data.get("label") or kind),
            argv=tuple(argv),
            paths=tuple(paths),
            timeout_seconds=timeout,
            declaration=raw_declaration,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "argv": list(self.argv),
            "paths": list(self.paths),
            "timeout_seconds": self.timeout_seconds,
            "declaration": self.declaration,
            "declare_host_deny": self.declare_host_deny,
        }


@dataclass(frozen=True, slots=True)
class Config:
    schema: int
    repo: str
    home: str
    gates: dict[str, GateConfig]
    budget: BudgetPolicy
    created_at: str
    updated_at: str
    execution_profile: str = profile_module.DEFAULT_PROFILE
    native_turbo_attestation: profile_module.NativeTurboAttestation | None = None

    def __post_init__(self) -> None:
        profile_module.parse_profile(self.execution_profile)
        if self.execution_profile == profile_module.NATIVE_TURBO and self.native_turbo_attestation is None:
            raise CorruptState("native-turbo execution profile needs an operator attestation")
        if self.execution_profile != profile_module.NATIVE_TURBO and self.native_turbo_attestation is not None:
            raise CorruptState("a manual execution profile cannot keep a native Turbo attestation")

    @classmethod
    def from_dict(cls, data: Any) -> Config:
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise CorruptState("unsupported config schema")
        gates_raw = data.get("gates")
        if not isinstance(gates_raw, dict):
            raise CorruptState("config.gates must be an object")
        gates: dict[str, GateConfig] = {}
        for name, value in gates_raw.items():
            if not isinstance(name, str):
                raise CorruptState("gate names must be strings")
            gates[name] = GateConfig.from_dict(value)
        execution_profile = profile_module.parse_profile(data.get("execution_profile", profile_module.DEFAULT_PROFILE))
        attestation = profile_module.parse_attestation(data.get("native_turbo_attestation"), execution_profile)
        return cls(
            schema=SCHEMA,
            repo=str(data.get("repo") or ""),
            home=str(data.get("home") or ""),
            gates=gates,
            budget=BudgetPolicy.from_dict(data.get("budget")),
            created_at=str(data.get("created_at") or ""),
            updated_at=str(data.get("updated_at") or ""),
            execution_profile=execution_profile,
            native_turbo_attestation=attestation,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "repo": self.repo,
            "home": self.home,
            "gates": {key: value.to_dict() for key, value in sorted(self.gates.items())},
            "budget": self.budget.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "execution_profile": self.execution_profile,
            "native_turbo_attestation": None if self.native_turbo_attestation is None else self.native_turbo_attestation.to_dict(),
        }


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def skeleton(paths: RuntimePaths) -> Config:
    stamp = now()
    return Config(
        schema=SCHEMA,
        repo=str(paths.repo),
        home=str(paths.home),
        gates={},
        budget=BudgetPolicy(),
        created_at=stamp,
        updated_at=stamp,
    )


def load(paths: RuntimePaths) -> Config:
    data = read_json(paths.config, paths.home)
    if data is None:
        raise UsageError(f"config missing at {paths.config}; run init first")
    return Config.from_dict(data)


def save(paths: RuntimePaths, config: Config) -> None:
    safe_dir(paths.home, create=True)
    atomic_json(paths.config, replace(config, updated_at=now()).to_dict(), paths.home)


def require_binding(config: Config, paths: RuntimePaths) -> None:
    if config.repo != str(paths.repo) or config.home != str(paths.home):
        raise UsageError(f"config is bound to repo={config.repo} home={config.home}, not the supplied paths")


def completeness_issues(config: Config) -> list[str]:
    issues: list[str] = []
    for name in GATE_NAMES:
        if name not in config.gates:
            issues.append(f"gate {name} is not configured")
    one = config.gates.get("1")
    if one is not None:
        if one.kind != "command" or not one.argv:
            issues.append("gate 1 needs a command argv")
        if one.declaration not in (profile_module.HOST_DENIES_WRITES, profile_module.HOST_POLICY_PROBED):
            issues.append("gate 1 needs an operator host-policy declaration")
        if config.execution_profile == profile_module.NATIVE_TURBO and one.declaration != profile_module.HOST_POLICY_PROBED:
            issues.append("native-turbo gate 1 needs the operator-probed host-policy declaration")
    two = config.gates.get("2")
    if two is not None and (two.kind != "command" or not two.argv):
        issues.append("gate 2 needs a command argv")
    three = config.gates.get("3")
    if three is not None and (three.kind != "protected-paths" or not three.paths):
        issues.append("gate 3 needs at least one protected path")
    if not config.budget.timezone:
        issues.append("budget timezone is not declared")
    else:
        try:
            ZoneInfo(config.budget.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            issues.append(f"budget timezone is invalid: {config.budget.timezone}")
    return issues


def require_complete(config: Config) -> None:
    issues = completeness_issues(config)
    if issues:
        raise UsageError("gate configuration incomplete: " + "; ".join(issues))


def for_run(paths: RuntimePaths, run: Any) -> Config:
    conf = load(paths)
    require_binding(conf, paths)
    require_complete(conf)
    if digest(conf) != run.gate_digest:
        raise UsageError(
            "gate configuration changed (digest mismatch); the run cannot continue until the operator reconciles it"
        )
    return conf


def digest(config: Config) -> str:
    canonical: dict[str, Any] = {
        "schema": SCHEMA,
        "execution_profile": config.execution_profile,
        "native_turbo_attestation": None if config.native_turbo_attestation is None else config.native_turbo_attestation.to_dict(),
        "budget_policy": {
            "weekly_usd": config.budget.weekly_usd,
            "bugfix_usd": config.budget.bugfix_usd,
            "stop_usd": config.budget.stop_usd,
            "timezone": config.budget.timezone,
        },
        "gates": {},
    }
    for name in GATE_NAMES:
        gate = config.gates.get(name)
        if gate is None:
            canonical["gates"][name] = None
            continue
        canonical["gates"][name] = {
            "kind": gate.kind,
            "argv": list(gate.argv),
            "paths": list(gate.paths),
            "timeout_seconds": gate.timeout_seconds,
            "declaration": gate.declaration,
        }
    text = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def with_profile(
    config: Config,
    execution_profile: str,
    attestation: profile_module.NativeTurboAttestation | None,
) -> Config:
    updated = replace(
        config,
        execution_profile=execution_profile,
        native_turbo_attestation=attestation,
    )
    if execution_profile == profile_module.NATIVE_TURBO:
        one = updated.gates.get("1")
        if one is not None and one.declaration != profile_module.HOST_POLICY_PROBED:
            raise UsageError(
                "native-turbo needs gate 1 reconfigured with --declare-host-probed; "
                "the host is not claimed to deny writes"
            )
    return updated


def with_gate(config: Config, name: str, gate: GateConfig) -> Config:
    return replace(config, gates={**config.gates, name: gate})


def with_timezone(config: Config, name: str) -> Config:
    return replace(config, budget=replace(config.budget, timezone=name))


def with_week(config: Config, week: str, spend: WeekSpend) -> Config:
    return replace(config, budget=replace(config.budget, weeks={**config.budget.weeks, week: spend}))


def protected_entry_issue(entry: str) -> str | None:
    """Why a protected-path entry cannot name a repository path, or None when it can."""
    if not entry.strip():
        return "must not be blank"
    if entry != entry.strip():
        return "must not have leading or trailing whitespace"
    path = PurePosixPath(entry)
    if path.is_absolute():
        return "must be repository-relative"
    if ".." in path.parts:
        return "must not contain a parent traversal"
    return None


def protected_match(relative: str, protected: tuple[str, ...]) -> bool:
    path = PurePosixPath(relative)
    for item in protected:
        entry = PurePosixPath(item)
        if path == entry or entry in path.parents:
            return True
    return False
