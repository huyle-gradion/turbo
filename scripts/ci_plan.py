#!/usr/bin/env python3
"""Plan Turbo's own CI run: the touched areas' tests, or the full suite in shards (#115).

CI runs this file from the trusted base commit against the candidate checkout
given by --repo, so a pull request cannot change its own plan. It imports
nothing from --repo. Output is one JSON object on stdout:

    {"mode": "docs-only" | "areas" | "full", "reason": str, "smoke": bool,
     "jobs": [{"name": "area:<name>" | "shard:<n>", "tests": [path, ...]}]}

This is Turbo's CI policy only. The factory's runtime selection for child
deliveries stays in factory/ci_selection.py and is not changed by this map.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import Path

# Any change here, or under a listed directory, runs the full suite. Mirrors
# factory.ci_selection.FULL_SUITE_TRIGGER_PATHS; scripts/ covers this planner.
FULL_SUITE_TRIGGERS = (
    ".github", "factory.json", "bin", "scripts", "guards", "pyproject.toml",
    "tests/support.py", "tests/test_bundle.py", "tests/test_cli_paths.py",
    "tests/test_evidence_integrity.py", "tests/test_smoke_script.py",
    "factory/ci_selection.py", "factory/ci_gate.py", "factory/deliver_checks.py",
    "factory/config.py", "factory/gates.py", "factory/runner.py", "factory/sandbox.py",
    "factory/__init__.py", "factory/__main__.py", "factory/args.py", "factory/cli.py",
    "factory/errors.py", "factory/gitio.py", "factory/integrity.py", "factory/jsonshape.py",
    "factory/limits.py", "factory/model.py", "factory/paths.py", "factory/store.py",
    "factory/worker.py",
)

# Path pattern -> areas, first match wins. A trailing "/" matches the whole
# directory; otherwise "*" stays within one path segment. () means docs only.
# Test files are matched against the same table to build each area's tests.
AREA_MAP = (
    ("docs/security-review/", ("review",)),
    ("docs/", ()),
    ("pilot/", ()),
    ("*.md", ()),
    ("LICENSE", ()),
    ("VERSION", ()),
    (".gitignore", ()),
    ("examples/*.example.json", ()),
    ("examples/qualification/", ("qualification",)),
    ("skills/", ("skills",)),
    ("tests/security_review/test_security_review.py", ("review", "skills")),
    ("factory/independent_review/", ("review",)),
    ("factory/security_review/", ("review",)),
    ("factory/automated_qa/", ("review",)),
    ("tests/independent_review/", ("review",)),
    ("tests/security_review/", ("review",)),
    ("tests/automated_qa/", ("review",)),
    ("factory/qualification.py", ("qualification",)),
    ("tests/test_qualification*.py", ("qualification",)),
    ("tests/qualification_offline.py", ("qualification",)),
    ("factory/deliver.py", ("delivery",)),
    ("factory/integration.py", ("delivery",)),
    ("factory/lifecycle.py", ("delivery",)),
    ("tests/test_deliver*.py", ("delivery",)),
    ("tests/test_delivery_*.py", ("delivery",)),
    ("tests/test_integration.py", ("delivery",)),
    ("tests/support_deliver.py", ("delivery", "qualification")),
    ("tests/test_bundle.py", ("skills", "core")),
    ("factory/*.py", ("core",)),
    ("tests/test_*.py", ("core",)),
)
AREA_ORDER = ("skills", "core", "delivery", "review", "qualification")
# Delivery code and tests import the review packages and their test helpers,
# so a code or test change there also runs the delivery tests.
REVIEW_PACKAGES = tuple(f"{root}/{pkg}/" for root in ("factory", "tests")
                        for pkg in ("independent_review", "security_review", "automated_qa"))
SMOKE_PREFIXES = ("factory/", "bin/", "scripts/", "skills/")


def matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return path.count("/") == pattern.count("/") and fnmatch.fnmatchcase(path, pattern)


def areas_of(path: str) -> tuple[str, ...] | None:
    """The areas a path belongs to, () for docs, or None when unmapped."""
    for pattern, areas in AREA_MAP:
        if matches(path, pattern):
            return areas
    return None


def is_trigger(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in FULL_SUITE_TRIGGERS)


def test_files(repo: Path) -> list[str]:
    return sorted(p.relative_to(repo).as_posix() for p in (repo / "tests").rglob("test_*.py"))


def full_plan(repo: Path, shards: int, reason: str) -> dict:
    """Spread every test file over shards, largest first onto the lightest shard."""
    files = test_files(repo)
    count = max(1, min(shards, len(files)))
    loads = [[0, 0, []] for _ in range(count)]  # bytes, files, tests
    for name in sorted(files, key=lambda f: (-(repo / f).stat().st_size, f)):
        load = min(loads, key=lambda entry: (entry[0], entry[1]))
        load[0] += (repo / name).stat().st_size
        load[1] += 1
        load[2].append(name)
    jobs = [{"name": f"shard:{i}", "tests": sorted(load[2])} for i, load in enumerate(loads, 1)]
    return {"mode": "full", "reason": reason, "smoke": True, "jobs": jobs}


def plan(repo: Path, changed: list[str], deleted: list[str], event: str, shards: int) -> dict:
    if event != "pull_request":
        return full_plan(repo, shards, f"{event} event runs the full suite")
    if not changed:
        return full_plan(repo, shards, "no changed paths")
    if any(p.startswith("tests/") and p.endswith(".py") for p in deleted):
        return full_plan(repo, shards, "a test file was deleted")
    touched: set[str] = set()
    for path in changed:
        if is_trigger(path):
            return full_plan(repo, shards, f"CI or verification-chain path changed: {path}")
        areas = areas_of(path)
        if areas is None:
            return full_plan(repo, shards, f"unmapped path: {path}")
        touched.update(areas)
        if path.startswith(REVIEW_PACKAGES):
            touched.add("delivery")
    smoke = any(p.startswith(SMOKE_PREFIXES) for p in changed)
    if not touched:
        return {"mode": "docs-only", "reason": "documentation and examples only", "smoke": smoke, "jobs": []}
    jobs, seen = [], set()
    for area in AREA_ORDER:
        if area not in touched:
            continue
        tests = [t for t in test_files(repo) if area in (areas_of(t) or ()) and t not in seen]
        seen.update(tests)
        if tests:
            jobs.append({"name": f"area:{area}", "tests": tests})
    if not jobs:
        return full_plan(repo, shards, "touched areas have no test files")
    names = ", ".join(sorted(touched))
    return {"mode": "areas", "reason": f"touched areas: {names}", "smoke": smoke, "jobs": jobs}


def read_paths(path: str | None) -> list[str]:
    if not path:
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="candidate checkout to plan for")
    parser.add_argument("--changed-file", help="file listing changed paths, one per line")
    parser.add_argument("--deleted-file", help="file listing deleted paths, one per line")
    parser.add_argument("--event", default="pull_request", help="GitHub event name")
    parser.add_argument("--shards", type=int, default=4, help="parallel jobs for the full suite")
    args = parser.parse_args()
    if args.shards < 1:
        parser.error("--shards must be at least 1")
    result = plan(Path(args.repo).resolve(), read_paths(args.changed_file),
                  read_paths(args.deleted_file), args.event, args.shards)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
