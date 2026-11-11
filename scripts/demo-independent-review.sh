#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/tests:$ROOT:${PYTHONPATH:-}"

TMP_DIR="${DEMO_KEEP_EVIDENCE_DIR:-$(mktemp -d)}"
if [[ -z "${DEMO_KEEP_EVIDENCE_DIR:-}" ]]; then
  trap 'rm -rf "$TMP_DIR"' EXIT
fi

python3 -c '
import json, pathlib, sys
from tests.independent_review.test_independent_review import run_disposable_demo
summary = run_disposable_demo(pathlib.Path(sys.argv[1]))
print(json.dumps(summary, indent=2, sort_keys=True))
print("DEMO_INDEPENDENT_REVIEW_OK")
' "$TMP_DIR"
