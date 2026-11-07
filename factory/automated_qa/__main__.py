"""CLI entrypoint for automated QA delivery and bounded correction loop (Issue #21)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from factory.automated_qa import run_from_cli
from factory.errors import PolicyError, UsageError
from factory.paths import resolve_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m factory.automated_qa")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--time-limit", default="15m")
    parser.add_argument("--agy-bin", default="agy")
    parser.add_argument("--qa-cases-file", default=None)
    parser.add_argument("--max-correction-attempts", type=int, default=2)
    parser.add_argument("--input-rate-usd-per-1m", type=float, default=None)
    parser.add_argument("--output-rate-usd-per-1m", type=float, default=None)
    parser.add_argument("--approve-parent-acceptance", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        res = run_from_cli(resolve_paths(args.repo, args.home), args)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"automated-qa {res.task_gid}: {res.status} (ci_verified={res.ci_verified}, qa_verified={res.qa_verified})")
        return 0 if res.qa_verified else 1
    except PolicyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"filesystem error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BROAD_EXCEPT_OK - CLI boundary, no traceback
        print(f"internal error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
