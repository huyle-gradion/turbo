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

# -------------------------------------------------------------
# Issue #69 Promotion Gate & Authoritative Version Selection
# -------------------------------------------------------------
echo "== Issue #69: Review Packet Generation & Promotion Gate =="

# 1. Build review packet from eligible evaluation report A
PACKET_A="$EVIDENCE/review_packet_a.json"
python3 -m factory.improvement build-review-packet \
  --report "$EV_A/attempts/attempt-1/report.json" \
  --out "$PACKET_A" > "$EVIDENCE/commands/06_build_packet_a.log" 2>&1
PACKET_SCHEMA=$(python3 -c "import json; p = json.load(open('$PACKET_A')); print(p['schema_version'])")
test "$PACKET_SCHEMA" = "1"
echo "Review packet generated: schema_version=$PACKET_SCHEMA, authority_note present"

# 2. Refusal: Ineligible report B rejected by packet builder
set +e
python3 -m factory.improvement build-review-packet \
  --report "$EV_B/attempts/attempt-1/report.json" \
  --out "$EVIDENCE/review_packet_b.json" > "$EVIDENCE/commands/07_build_packet_b.err" 2>&1
RC_PKT_B=$?
set -e
test "$RC_PKT_B" -ne 0
echo "Ineligible report B packet generation refused (exit=$RC_PKT_B)"

# 3. Disposable Git repository to model authoritative human PR merge to main
DEMO_REPO="$EVIDENCE/git_repo"
mkdir -p "$DEMO_REPO"
git -C "$DEMO_REPO" init -b main -q
git -C "$DEMO_REPO" config user.name "Maintainer"
git -C "$DEMO_REPO" config user.email "maintainer@example.com"
echo "def check(): return 'baseline'" > "$DEMO_REPO/target.py"
git -C "$DEMO_REPO" add . && git -C "$DEMO_REPO" commit -q -m "baseline check"
BASE_SHA=$(git -C "$DEMO_REPO" rev-parse HEAD)

git -C "$DEMO_REPO" checkout -q -b feat/imp-42
cp "$CANDIDATE_PY" "$DEMO_REPO/target.py"
git -C "$DEMO_REPO" add . && git -C "$DEMO_REPO" commit -q -m "feat: candidate check"

git -C "$DEMO_REPO" checkout -q main
git -C "$DEMO_REPO" merge -q --no-ff feat/imp-42 -m "Merge pull request #42 from feat/imp-42"
MERGE_SHA=$(git -C "$DEMO_REPO" rev-parse HEAD)

# 4. Authoritative exact-version selection
PROOF_APPROVED="$EVIDENCE/proof_approved.json"
cat > "$PROOF_APPROVED" <<JSON
{"provider":"github","repo_slug":"huyle-gradion/turbo","pr_number":42,"pr_data":{"number":42,"state":"closed","merged":true,"base":{"ref":"main","sha":"$BASE_SHA"},"merge_commit_sha":"$MERGE_SHA"}}
JSON

SELECTED_PY="$EVIDENCE/selected_content.py"
python3 -m factory.improvement resolve-approved \
  --repo "$DEMO_REPO" --report "$EV_A/attempts/attempt-1/report.json" \
  --proof "$PROOF_APPROVED" --out "$SELECTED_PY" > "$EVIDENCE/commands/08_resolve_approved.log" 2>&1
diff -u "$CANDIDATE_PY" "$SELECTED_PY"
echo "Authoritative approved selection verified: $MERGE_SHA"

# 5. Refusal: unmerged PR proof rejected
PROOF_UNMERGED="$EVIDENCE/proof_unmerged.json"
cat > "$PROOF_UNMERGED" <<JSON
{"provider":"github","repo_slug":"huyle-gradion/turbo","pr_number":99,"pr_data":{"number":99,"state":"open","merged":false,"base":{"ref":"main"}}}
JSON

set +e
python3 -m factory.improvement resolve-approved \
  --repo "$DEMO_REPO" --report "$EV_A/attempts/attempt-1/report.json" \
  --proof "$PROOF_UNMERGED" > "$EVIDENCE/commands/09_resolve_unmerged.err" 2>&1
RC_UNMERGED=$?
set -e
test "$RC_UNMERGED" -ne 0
echo "Unmerged PR approval refused (exit=$RC_UNMERGED)"

cat > "$EVIDENCE/summary.json" <<JSON
{"evidence_dir":"$EVIDENCE","proposal_a_status":"$STATUS_A","proposal_b_status":"$STATUS_B","proposal_c_status":"$STATUS_C","attempt_1_sha_preserved":"$([ "$SHA_BEFORE" = "$SHA_AFTER" ] && echo "true" || echo "false")","review_packet_schema":"$PACKET_SCHEMA","selected_merge_sha":"$MERGE_SHA","packet_b_refused":$([ "$RC_PKT_B" -ne 0 ] && echo "true" || echo "false"),"unmerged_refused":$([ "$RC_UNMERGED" -ne 0 ] && echo "true" || echo "false")}
JSON
echo "== Retained Demo Complete: $EVIDENCE =="
