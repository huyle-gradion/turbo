"""Typed failures for the private factory."""

from __future__ import annotations


class FactoryError(Exception):
    """Base class for expected, operator-facing failures."""


class UsageError(FactoryError):
    """Invalid input, missing configuration, or an unsafe precondition."""


class PolicyError(FactoryError):
    """A gate, budget, or admission rule refused the action."""


class CorruptState(UsageError):
    """A stored file no longer matches the documented schema."""
