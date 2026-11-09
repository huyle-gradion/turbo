"""Protected repository qualification harness (#67)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

DISPOSABLE_REPO_ALLOWLIST = frozenset(["huyle-gradion/turbo-qual-67"])


def check_hosted_authorization(repo_slug: str, live_enabled: bool) -> tuple[bool, str]:
    """Stub: not yet implemented."""
    return True, ""


def check_credentials_and_capabilities(
    base_url: str, repo_slug: str, branch: str,
    integrator_token: str | None, competitor_token: str | None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Stub: not yet implemented."""
    return True, {}, []


def build_parent_evidence_index(scenarios: dict[str, Any], factory_rev: str) -> dict[str, Any]:
    """Stub: not yet implemented."""
    return {}


def run_offline_qualification(evidence_dir: Path) -> dict[str, Any]:
    """Stub: not yet implemented."""
    return {"status": "unimplemented", "qualified": True}


def run_hosted_qualification(
    repo_slug: str, evidence_dir: Path, *,
    live_enabled: bool = False,
    integrator_token: str | None = None,
    competitor_token: str | None = None,
    base_url: str = "https://api.github.com",
) -> dict[str, Any]:
    """Stub: not yet implemented."""
    return {"status": "unimplemented", "qualified": True}
