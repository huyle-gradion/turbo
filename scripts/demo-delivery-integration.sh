#!/usr/bin/env bash
# Offline demonstration of Issue #78: final delivery confirmed integration and completion lifecycle.
# 1. Confirmed delivery success -> completed, merged=True, landed_sha
# 2. Stale-base rejection -> merged=False, landed_sha=None
# 3. Provider permission denial -> denied-permissions, merged=False, delivery_approved=True
# 4. Provider timeout/uncertain outcome -> uncertain, merged=False, delivery_approved=True
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/tests:$ROOT:${PYTHONPATH:-}"

EVIDENCE_DIR="${DEMO_KEEP_EVIDENCE_DIR:-${EVIDENCE:-$(mktemp -d /tmp/turbo-delivery-integration-demo.XXXXXX)}}"
if [[ -z "${DEMO_KEEP_EVIDENCE_DIR:-}" && -z "${EVIDENCE:-}" ]]; then
  trap 'rm -rf "$EVIDENCE_DIR"' EXIT
fi
mkdir -p "$EVIDENCE_DIR"

python3 -c '
import json, pathlib, sys
from support_deliver import run_delivery_integration_demo

evidence_dir = pathlib.Path(sys.argv[1])
try:
    summary = run_delivery_integration_demo(evidence_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("DEMO_DELIVERY_INTEGRATION_OK")
except Exception as exc:
    print(f"DEMO_DELIVERY_INTEGRATION_FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
' "$EVIDENCE_DIR"
