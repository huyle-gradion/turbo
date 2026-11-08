#!/usr/bin/env bash
# Offline demonstration of Issue #65: protected child integration lifecycle.
# 1. Successful approved integration -> confirmed
# 2. Boundary competition -> rejected-competing-base
# 3. Stale approval / changed base -> stale-candidate-revision
# 4. Unsupported protection -> unsupported-protection
# 5. Provider timeout during merge -> uncertain
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/tests:$ROOT:${PYTHONPATH:-}"

EVIDENCE_DIR="${DEMO_KEEP_EVIDENCE_DIR:-${EVIDENCE:-$(mktemp -d /tmp/turbo-integration-demo.XXXXXX)}}"
if [[ -z "${DEMO_KEEP_EVIDENCE_DIR:-}" && -z "${EVIDENCE:-}" ]]; then
  trap 'rm -rf "$EVIDENCE_DIR"' EXIT
fi
mkdir -p "$EVIDENCE_DIR"

python3 -c '
import json, pathlib, sys
from support_deliver import run_integration_demo

evidence_dir = pathlib.Path(sys.argv[1])
try:
    summary = run_integration_demo(evidence_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("DEMO_CHILD_INTEGRATION_OK")
except Exception as exc:
    print(f"DEMO_CHILD_INTEGRATION_FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
' "$EVIDENCE_DIR"
