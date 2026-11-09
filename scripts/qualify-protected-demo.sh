#!/usr/bin/env bash
# Repeatable qualification harness for protected repository demonstration (#67).
# Exercises actual A+B delivery/integration implementation against explicitly
# allowlisted disposable repository or offline simulated environment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/tests:$ROOT:${PYTHONPATH:-}"

EVIDENCE_DIR="${DEMO_KEEP_EVIDENCE_DIR:-${EVIDENCE:-$(mktemp -d /tmp/turbo-qual-67.XXXXXX)}}"
if [[ -z "${DEMO_KEEP_EVIDENCE_DIR:-}" && -z "${EVIDENCE:-}" ]]; then
  trap 'rm -rf "$EVIDENCE_DIR"' EXIT
fi
mkdir -p "$EVIDENCE_DIR"

python3 -m factory.qualification --evidence-dir "$EVIDENCE_DIR" "$@"
