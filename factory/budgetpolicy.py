"""Operator-declared weekly budget policy and spend records."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from factory.errors import CorruptState


@dataclass(frozen=True, slots=True)
class WeekSpend:
    usd: float | None
    state: str
    source: str
    recorded_at: str
    verification: str = "operator-declared; not independently verified"

    @classmethod
    def from_dict(cls, data: Any) -> WeekSpend:
        if not isinstance(data, dict):
            raise CorruptState("week spend must be an object")
        state = data.get("state")
        if state not in ("known", "unknown"):
            raise CorruptState(f"week spend state invalid: {state!r}")
        usd = data.get("usd")
        if state == "known" and (
            isinstance(usd, bool) or not isinstance(usd, (int, float)) or not math.isfinite(usd) or usd < 0
        ):
            raise CorruptState("known spend needs a finite non-negative number")
        if state == "unknown":
            usd = None
        return cls(
            usd=None if usd is None else float(usd),
            state=str(state),
            source=str(data.get("source") or ""),
            recorded_at=str(data.get("recorded_at") or ""),
            verification=str(data.get("verification") or "operator-declared; not independently verified"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "usd": self.usd,
            "state": self.state,
            "source": self.source,
            "recorded_at": self.recorded_at,
            "verification": self.verification,
        }


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    weekly_usd: float = 200.0
    bugfix_usd: float = 160.0
    stop_usd: float = 200.0
    timezone: str | None = None
    source: str = "operator brief: shared quota about $200 per week; bug-fix about 80 percent or $160; stop at about $200 until Monday; reset timezone operator-declared"
    weeks: dict[str, WeekSpend] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> BudgetPolicy:
        if not isinstance(data, dict):
            raise CorruptState("budget must be an object")
        weeks_raw = data.get("weeks", {})
        if not isinstance(weeks_raw, dict):
            raise CorruptState("budget.weeks must be an object")
        weeks: dict[str, WeekSpend] = {}
        for key, value in weeks_raw.items():
            if not isinstance(key, str):
                raise CorruptState("budget week keys must be strings")
            weeks[key] = WeekSpend.from_dict(value)
        timezone_name = data.get("timezone")
        if timezone_name is not None and not isinstance(timezone_name, str):
            raise CorruptState("budget.timezone must be a string or null")
        return cls(
            weekly_usd=_number(data, "weekly_usd", 200.0),
            bugfix_usd=_number(data, "bugfix_usd", 160.0),
            stop_usd=_number(data, "stop_usd", 200.0),
            timezone=timezone_name,
            source=str(data.get("source") or ""),
            weeks=weeks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "weekly_usd": self.weekly_usd,
            "bugfix_usd": self.bugfix_usd,
            "stop_usd": self.stop_usd,
            "timezone": self.timezone,
            "source": self.source,
            "weeks": {key: value.to_dict() for key, value in sorted(self.weeks.items())},
        }


def _number(data: dict[str, Any], name: str, default: float) -> float:
    value = data.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise CorruptState(f"budget.{name} must be a finite non-negative number")
    return float(value)
