"""Weekly budget position. Unknown spend is never treated as zero.

Policy, in order: an unrecorded week is UNPRICED and blocks everything; at or above the weekly
stop every kind stops; from the bug-fix line to the stop only bug work continues; below the
bug-fix line every kind continues.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from factory.budgetpolicy import BudgetPolicy, WeekSpend
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.model import BudgetPosition


def week_key(policy: BudgetPolicy, moment: datetime | None = None) -> str:
    if not policy.timezone:
        raise UsageError("budget timezone is not declared; run configure --timezone")
    try:
        zone = ZoneInfo(policy.timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise UsageError(f"invalid budget timezone: {policy.timezone}") from exc
    local = (moment or datetime.now(timezone.utc)).astimezone(zone)
    year, week, _ = local.isocalendar()
    return f"{year}-W{week:02d}"


def position(policy: BudgetPolicy, moment: datetime | None = None) -> BudgetPosition:
    week = week_key(policy, moment)
    spend = policy.weeks.get(week)
    if spend is None or spend.state != "known" or spend.usd is None:
        raise PolicyError(f"UNPRICED: no known spend declaration for {week}; unknown spend is not zero")
    return BudgetPosition(
        week=week,
        state="known",
        usd=spend.usd,
        source=spend.source,
        recorded_at=spend.recorded_at,
        verification=spend.verification,
        weekly_usd=policy.weekly_usd,
        bugfix_usd=policy.bugfix_usd,
        stop_usd=policy.stop_usd,
    )


def violation(policy: BudgetPolicy, kind: str, current: BudgetPosition) -> str | None:
    if current.usd is None:
        return f"UNPRICED: no known spend declaration for {current.week}; unknown spend is not zero"
    if current.usd >= policy.stop_usd:
        return (
            f"weekly stop reached for {current.week}: declared spend {current.usd:.2f} >= "
            f"{policy.stop_usd:.2f}; all work stops until the week resets"
        )
    if kind != "bug" and current.usd >= policy.bugfix_usd:
        return (
            f"bug-fix quota reached for {current.week}: declared spend {current.usd:.2f} >= "
            f"{policy.bugfix_usd:.2f}; only bug work remains admissible below the "
            f"{policy.stop_usd:.2f} weekly stop"
        )
    return None


def attestation(policy: BudgetPolicy, kind: str, moment: datetime | None = None) -> BudgetPosition:
    current = position(policy, moment)
    reason = violation(policy, kind, current)
    if reason is not None:
        raise PolicyError(reason)
    return current


def record(policy: BudgetPolicy, week: str, usd: float | None, source: str) -> WeekSpend:
    if not source.strip():
        raise UsageError("spend record needs an explicit --source (declaration, not verified billing)")
    if usd is not None and (not math.isfinite(usd) or usd < 0):
        raise UsageError("spend must be a finite non-negative number")
    return WeekSpend(
        usd=usd,
        state="unknown" if usd is None else "known",
        source=source.strip(),
        recorded_at=now(),
    )


def show(policy: BudgetPolicy, week: str | None = None) -> tuple[str, WeekSpend | None]:
    key = week or week_key(policy)
    return key, policy.weeks.get(key)
