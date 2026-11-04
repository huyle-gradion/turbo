"""Operator-attested execution profile.

The helper never detects a host mode, reads a screenshot, changes host settings, or proves a
sandbox. A profile is a declaration the operator writes down. Native Turbo means the operator
selected the host's own unrestricted mode and probed its current behaviour; the helper only records
that statement and dispatches one explicit ordered bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from factory.errors import CorruptState
from factory.jsonshape import mapping, text

MANUAL = "manual"
NATIVE_TURBO = "native-turbo"
PROFILES = (MANUAL, NATIVE_TURBO)
DEFAULT_PROFILE = MANUAL
VERIFIED_BY_MANUAL = "manual"
VERIFIED_BY_VERIFY = "native-turbo-verify"
VERIFIED_BY = (VERIFIED_BY_MANUAL, VERIFIED_BY_VERIFY)

HOST_DENIES_WRITES = "host-denies-writes"
HOST_POLICY_PROBED = "host-policy-operator-probed"
NOT_APPLICABLE = "not-applicable"
DECLARATIONS = (HOST_DENIES_WRITES, HOST_POLICY_PROBED, NOT_APPLICABLE)

DEFAULT_HOST = "antigravity-native"
STATEMENT = (
    "operator selected the native Antigravity Turbo host and probed its current permission "
    "behaviour; this is a declaration, not a sandbox, permission, or QC proof"
)


@dataclass(frozen=True, slots=True)
class NativeTurboAttestation:
    host: str
    declaration: str = HOST_POLICY_PROBED
    statement: str = STATEMENT
    declared_at: str = ""

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise CorruptState("native Turbo attestation needs a host name")
        if self.declaration != HOST_POLICY_PROBED:
            raise CorruptState("native Turbo attestation cannot claim a validated write denial")
        if not self.statement.strip():
            raise CorruptState("native Turbo attestation needs an operator statement")

    @classmethod
    def from_dict(cls, data: Any) -> NativeTurboAttestation:
        raw = mapping(data, "native Turbo attestation")
        return cls(
            host=str(text(raw.get("host"), "attestation.host")),
            declaration=str(text(raw.get("declaration"), "attestation.declaration")),
            statement=str(text(raw.get("statement"), "attestation.statement")),
            declared_at=str(raw.get("declared_at") or ""),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "host": self.host,
            "declaration": self.declaration,
            "statement": self.statement,
            "declared_at": self.declared_at,
        }


def _require_profile_name(value: str) -> str:
    if value not in PROFILES:
        raise CorruptState(f"unknown execution profile: {value!r}")
    return value


def parse_profile(value: Any) -> str:
    if not isinstance(value, str):
        raise CorruptState("execution_profile must be a string")
    return _require_profile_name(value)


def parse_attestation(value: Any, profile: str) -> NativeTurboAttestation | None:
    if value is None:
        if profile == NATIVE_TURBO:
            raise CorruptState("native-turbo execution profile needs an operator attestation")
        return None
    attestation = NativeTurboAttestation.from_dict(value)
    if profile != NATIVE_TURBO:
        raise CorruptState("a manual execution profile cannot keep a native Turbo attestation")
    return attestation


def parse_run_identity(raw: dict[str, Any]) -> tuple[str, NativeTurboAttestation | None, str]:
    profile = parse_profile(raw.get("execution_profile", DEFAULT_PROFILE))
    attestation = parse_attestation(raw.get("profile_attestation"), profile)
    verified_by = raw.get("verified_by", VERIFIED_BY_MANUAL)
    if verified_by not in VERIFIED_BY:
        raise CorruptState(f"unknown verification mode: {verified_by!r}")
    return profile, attestation, verified_by


def require_host_declaration(profile: str, declaration: str) -> None:
    if profile == NATIVE_TURBO and declaration == HOST_DENIES_WRITES:
        raise CorruptState(
            "native Turbo cannot carry a host-denies-writes declaration; "
            "use --declare-host-probed for gate 1"
        )


def describe(profile: str, attestation: NativeTurboAttestation | None) -> str:
    if profile == NATIVE_TURBO and attestation is not None:
        return f"native-turbo ({attestation.host}; operator-attested, host not verified)"
    return "manual (one operator-approved command at a time)"
