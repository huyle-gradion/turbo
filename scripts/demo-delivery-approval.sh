#!/usr/bin/env bash
# Offline demonstration of Issue #62: four-stage disposable delivery approval lifecycle.
# 1. Blocker identified by reviewer -> delivery rejects
# 2. Ineffective correction -> reproducer fails -> delivery rejects
# 3. Verified correction -> reproducer passes -> exact candidate delivery approved
# 4. Subsequent revision -> stale approval reuse rejected
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/tests:$ROOT:${PYTHONPATH:-}"

EVIDENCE_DIR="${DEMO_KEEP_EVIDENCE_DIR:-$(mktemp -d /tmp/turbo-delivery-demo.XXXXXX)}"
if [[ -z "${DEMO_KEEP_EVIDENCE_DIR:-}" ]]; then
  trap 'rm -rf "$EVIDENCE_DIR"' EXIT
fi

python3 -c '
import json, pathlib, sys
from support_deliver import run_delivery_lifecycle_demo

evidence_dir = pathlib.Path(sys.argv[1])
try:
    summary = run_delivery_lifecycle_demo(evidence_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("DEMO_DELIVERY_APPROVAL_OK")
except Exception as exc:
    print(f"DEMO_DELIVERY_APPROVAL_FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
' "$EVIDENCE_DIR"
