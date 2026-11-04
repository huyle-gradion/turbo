"""Parse and enforce the operator-selected finite limits."""

from __future__ import annotations

import re

from factory.errors import UsageError

DURATION = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
COUNT = re.compile(r"^[0-9]+$")
RED_TIMEOUT = 900


def parse_count(raw: str, name: str) -> int:
    text = str(raw).strip()
    if COUNT.fullmatch(text) is None:
        raise UsageError(f"{name} must be a finite non-negative integer, got {raw!r}")
    return int(text)


def parse_duration(raw: str) -> int:
    text = str(raw).strip()
    if COUNT.fullmatch(text):
        return int(text)
    match = DURATION.fullmatch(text)
    if match is None or not any(match.groups()):
        raise UsageError(f"time limit must be seconds or <n>h<n>m<n>s, got {raw!r}")
    hours, minutes, seconds = (int(group) if group else 0 for group in match.groups())
    return hours * 3600 + minutes * 60 + seconds
