#!/usr/bin/env bash
# Repeatable qualification harness for protected repository demonstration (#67).
# Exercises actual A+B delivery/integration implementation against explicitly
# allowlisted disposable repository or offline simulated environment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

# Evidence is kept by default. Set DEMO_DELETE_EVIDENCE=1 to delete a generated
# evidence directory on exit; an explicitly named directory is never deleted.
EVIDENCE_DIR="${DEMO_KEEP_EVIDENCE_DIR:-${EVIDENCE:-}}"
if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/turbo-qual-67.XXXXXX")"
  if [[ "${DEMO_DELETE_EVIDENCE:-0}" == "1" ]]; then
    trap 'rm -rf "$EVIDENCE_DIR"' EXIT
  fi
fi
mkdir -p "$EVIDENCE_DIR"
echo "qualification evidence: $EVIDENCE_DIR" >&2

# Offline (the default) runs the simulated harness in tests/; hosted runs factory.qualification.
MODE=offline PREV=""
for ARG in "$@"; do
  [[ "$PREV" == --mode ]] && MODE="$ARG"
  [[ "$ARG" == --mode=* ]] && MODE="${ARG#--mode=}"
  PREV="$ARG"
done
MODULE=factory.qualification
[[ "$MODE" == offline ]] && MODULE=qualification_offline && PYTHONPATH="$ROOT/tests:$PYTHONPATH"  # test fakes: offline only
python3 -m "$MODULE" --evidence-dir "$EVIDENCE_DIR" "$@"
