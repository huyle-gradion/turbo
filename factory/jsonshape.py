"""JSON boundary helpers. Untrusted documents are narrowed once here."""

from __future__ import annotations

from typing import Any

from factory.errors import CorruptState


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorruptState(f"{name} must be an object")
    return value


def text(value: Any, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        raise CorruptState(f"{name} must be a non-empty string")
    return value


def integer(value: Any, name: str, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorruptState(f"{name} must be an integer")
    return value


def number(value: Any, name: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CorruptState(f"{name} must be a number")
    return float(value)


def items(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CorruptState(f"{name} must be a list")
    return value


def strings(value: Any, name: str) -> tuple[str, ...]:
    result: list[str] = []
    for item in items(value, name):
        parsed = text(item, name)
        if parsed is None:
            raise CorruptState(f"{name} must contain non-empty strings")
        result.append(parsed)
    return tuple(result)


def text_or_empty(value: Any, name: str) -> str:
    if value is None or value == "":
        return ""
    parsed = text(value, name)
    return "" if parsed is None else parsed
