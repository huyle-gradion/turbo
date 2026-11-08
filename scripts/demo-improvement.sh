#!/usr/bin/env bash
# Demonstration of Issue #68: Bounded factory-improvement proposals and comparison workflow.
# Retains all commands, exit statuses, input snapshots, reports, and hashes under $EVIDENCE.
set -euo pipefail

FACTORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$FACTORY_ROOT"
export PYTHONDONTWRITEBYTECODE=1

EVIDENCE="${EVIDENCE:-$(mktemp -d /tmp/turbo-68-evidence.XXXXXX)}"
export EVIDENCE

echo "== Demo Evidence Directory: $EVIDENCE =="
mkdir -p "$EVIDENCE/inputs" "$EVIDENCE/commands"

FAILURE_TXT="$EVIDENCE/inputs/observed_failure.txt"
printf "ERROR: check timed out on baseline\n" > "$FAILURE_TXT"

CANDIDATE_PY="$EVIDENCE/inputs/cand_check.py"
printf "def check(): return 'improved'\n" > "$CANDIDATE_PY"

CASES_JSON="$EVIDENCE/inputs/cases.json"
cat > "$CASES_JSON" <<'JSON'
{"improvement_cases":[{"case_id":"IMP-01","description":"Candidate succeeds where baseline fails","command":"python3 -c \"import sys, pathlib; p = pathlib.Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"","rubric":{"rubric_id":"R-IMP","summary":"exits 0 on improved","expected_exit_code":0,"required_output_tokens":[],"forbidden_output_tokens":[]}}],"regression_cases":[{"case_id":"REG-01","description":"Regression passes","command":"python3 -c \"import sys; sys.exit(0)\"","rubric":{"rubric_id":"R-REG","summary":"exits 0","expected_exit_code":0,"required_output_tokens":[],"forbidden_output_tokens":[]}}]}
JSON

# Proposal A (Improvement Eligible)
PROPOSAL_A="$EVIDENCE/inputs/proposal_a.json"
python3 -m factory.improvement create-proposal \
  --out "$PROPOSAL_A" --proposal-id "proposal-eligible" --failure-desc "Check timed out on baseline" \
  --failure-artifact "$FAILURE_TXT" --kind "check" --target-path "target.py" --content-file "$CANDIDATE_PY" \
  --baseline-identity "base-rev-1" --candidate-identity "cand-rev-2" --expected-improvement "Resolves timeout" \
  --cases-file "$CASES_JSON" > "$EVIDENCE/commands/01_create_proposal_a.log" 2>&1

EV_A="$EVIDENCE/eval_a"
python3 -m factory.improvement evaluate --proposal "$PROPOSAL_A" --evidence-dir "$EV_A" --json \
  > "$EVIDENCE/commands/02_eval_proposal_a.json" 2> "$EVIDENCE/commands/02_eval_proposal_a.err" || true
STATUS_A=$(python3 -c "import json; print(json.load(open('$EV_A/attempts/attempt-1/report.json'))['eligibility'])")
echo "Proposal A evaluation outcome: $STATUS_A"

# Proposal B (Failing Regression -> Ineligible)
CASES_FAILING_REG="$EVIDENCE/inputs/cases_failing_reg.json"
cat > "$CASES_FAILING_REG" <<'JSON'
{"improvement_cases":[{"case_id":"IMP-01","description":"Candidate succeeds where baseline fails","command":"python3 -c \"import sys, pathlib; p = pathlib.Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"","rubric":{"rubric_id":"R-IMP","summary":"exits 0 on improved","expected_exit_code":0,"required_output_tokens":[],"forbidden_output_tokens":[]}}],"regression_cases":[{"case_id":"REG-FAIL","description":"Fails on candidate","command":"python3 -c \"import sys, pathlib; sys.exit(1 if pathlib.Path('target.py').exists() else 0)\"","rubric":{"rubric_id":"R-REG-FAIL","summary":"exits 0","expected_exit_code":0,"required_output_tokens":[],"forbidden_output_tokens":[]}}]}
JSON

PROPOSAL_B="$EVIDENCE/inputs/proposal_b.json"
python3 -m factory.improvement create-proposal \
  --out "$PROPOSAL_B" --proposal-id "proposal-regression-fail" --failure-desc "Check timed out on baseline" \
  --failure-artifact "$FAILURE_TXT" --kind "check" --target-path "target.py" --content-file "$CANDIDATE_PY" \
  --baseline-identity "base-rev-1" --candidate-identity "cand-rev-2" --expected-improvement "Resolves timeout" \
  --cases-file "$CASES_FAILING_REG" > "$EVIDENCE/commands/03_create_proposal_b.log" 2>&1

EV_B="$EVIDENCE/eval_b"
set +e
python3 -m factory.improvement evaluate --proposal "$PROPOSAL_B" --evidence-dir "$EV_B" --json \
  > "$EVIDENCE/commands/04_eval_proposal_b.json" 2> "$EVIDENCE/commands/04_eval_proposal_b.err"
RC_B=$?
set -e
STATUS_B=$(python3 -c "import json; print(json.load(open('$EV_B/attempts/attempt-1/report.json'))['eligibility'])")
echo "Proposal B evaluation outcome (expected ineligible, exit=$RC_B): $STATUS_B"

# Simulate Interrupted Evaluation & Append-Only Retention
EV_C="$EVIDENCE/eval_c"
mkdir -p "$EV_C/attempts/attempt-1"
cat > "$EV_C/attempts/attempt-1/attempt-manifest.json" <<'JSON'
{"attempt_number":1,"status":"interrupted","eligibility":"ineligible","error":"KeyboardInterrupt"}
JSON
SHA_BEFORE=$(sha256sum "$EV_C/attempts/attempt-1/attempt-manifest.json" | awk '{print $1}')

# Repeat evaluation into EV_C -> confirms attempt-2 is created and attempt-1 is unmodified
python3 -m factory.improvement evaluate --proposal "$PROPOSAL_A" --evidence-dir "$EV_C" --json \
  > "$EVIDENCE/commands/05_eval_repeat.json" 2> "$EVIDENCE/commands/05_eval_repeat.err" || true
SHA_AFTER=$(sha256sum "$EV_C/attempts/attempt-1/attempt-manifest.json" | awk '{print $1}')
STATUS_C=$(python3 -c "import json; print(json.load(open('$EV_C/attempts/attempt-2/report.json'))['eligibility'])")

echo "Append-only demonstration: attempt-1 SHA unchanged ($([ "$SHA_BEFORE" = "$SHA_AFTER" ] && echo "YES" || echo "NO")), attempt-2 outcome: $STATUS_C"

cat > "$EVIDENCE/summary.json" <<JSON
{"evidence_dir":"$EVIDENCE","proposal_a_status":"$STATUS_A","proposal_b_status":"$STATUS_B","proposal_c_status":"$STATUS_C","attempt_1_sha_preserved":"$([ "$SHA_BEFORE" = "$SHA_AFTER" ] && echo "true" || echo "false")"}
JSON
echo "== Retained Demo Complete: $EVIDENCE =="
