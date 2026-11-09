# Verification Index: Issue #83

**Issue**: huyle-gradion/turbo#83: Persist uncertain integration evidence when landing confirmation times out  
**Base Commit**: `0da0239` (`main`)  
**Head Commit**: `90cf8fa` (`feat/issue-83-persist-uncertain-evidence`)  

---

## 1. Baseline Failures (`0da0239`)

Prior to the fix, `_confirm_landing` was invoked outside exception handlers in both post-PUT confirmation and reconciliation paths. Injected timeouts raised unhandled `AttemptTimeoutError`, skipping Step 11 result persistence and leaving no `integration-record.json` on disk.

### Baseline Failure 1: Post-PUT confirmation GET timeout
- **Command**:
  ```sh
  PYTHONPATH=tests:. python3 -c '... patch _http_req to raise AttemptTimeoutError on confirmation GET after PUT ...'
  ```
- **Exit Status**: 0 (demonstration script caught uncaught exception)
- **Observed Behavior**:
  ```
  BASELINE FAILED AS EXPECTED with uncaught exception: <class 'factory.deliver_checks.AttemptTimeoutError'> injected confirmation GET timeout
  integration-record.json exists?: False
  PUT count: 1
  ```

### Baseline Failure 2: Post-PUT confirmation git inspection timeout
- **Command**:
  ```sh
  PYTHONPATH=tests:. python3 -c '... patch git_timed to raise AttemptTimeoutError on "inspect landed commit" ...'
  ```
- **Exit Status**: 0
- **Observed Behavior**:
  ```
  BASELINE FAILED AS EXPECTED with uncaught exception: <class 'factory.deliver_checks.AttemptTimeoutError'> injected git inspection timeout
  integration-record.json exists?: False
  PUT count: 1
  ```

### Baseline Failure 3: Reconciliation confirmation timeout
- **Command**:
  ```sh
  PYTHONPATH=tests:. python3 -c '... patch _http_req to raise AttemptTimeoutError on second (confirmation) GET ...'
  ```
- **Exit Status**: 0
- **Observed Behavior**:
  ```
  BASELINE FAILED AS EXPECTED with uncaught exception in reconciliation: <class 'factory.deliver_checks.AttemptTimeoutError'> injected reconciliation confirmation GET timeout
  integration-record.json exists?: False
  Total PUT count: 1
  ```

---

## 2. Acceptance Criteria to Test Mapping

| Acceptance Group | Targeted Test | Seam & Coverage |
|---|---|---|
| **AC1**: Successful PUT, confirmation timeout | `test_confirmation_get_timeout_after_successful_put_persists_uncertainty` (`test_integration.py`) | Injects `AttemptTimeoutError` on confirmation GET after PUT; asserts normal return, `status="uncertain"`, `outcome="uncertain"`, `confirmation_status="uncertain"`, `mutation_outcome="succeeded"`, `landed_sha=None`, preserved request/record paths, exactly 1 PUT. |
| **AC1**: Successful PUT, confirmation git timeout | `test_confirmation_git_inspection_timeout_after_successful_put_persists_uncertainty` (`test_integration.py`) | Subtests for `"git fetch origin"`, `"inspect landed commit"`, `"verify landed parents"`. Asserts normal return, all 3 uncertain fields in result and record JSON, `mutation_outcome="succeeded"`, no landed SHA, exactly 1 PUT. |
| **AC2**: Reconciliation confirmation timeout | `test_reconciliation_confirmation_timeout_persists_uncertainty` (`test_integration.py`) | Retained request + remote merged state. Initial reconciliation GET establishes `closed/merged`, then confirmation GET or git inspection times out. Asserts `mutation_outcome="already-merged"`, `reconciled=True`, all 3 uncertain fields, no additional PUT. |
| **AC3**: Recovery & Delivery | `test_confirmation_get_timeout_after_successful_put_persists_uncertainty` & `test_reconciliation_confirmation_timeout_persists_uncertainty` | Fresh retry confirms existing landing, persists confirmed evidence, cumulative PUT count stays 1. |
| **AC3**: Delivery-level integration | `test_confirmation_timeout_preserves_approval_and_resumes_without_duplicate_put` (`test_deliver_integration.py`) | Confirmation timeout preserves delivery approval, cannot mark completed/merged; resumed delivery confirms completion without another PUT; main branch ref unchanged. |
| **AC4**: Evidence Integrity & Redaction | `test_confirmation_timeout_diagnostic_redacts_synthetic_secrets` (`test_integration.py`) | Synthetic raw and urlencoded secret markers in timeout diagnostics are redacted from `integration-request.json`, `integration-record.json`, and result blockers. |

---

## 3. Targeted Test Execution Results

Command executed:
```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:. python3 -m unittest test_integration test_deliver_integration -v
```
Output:
```
Ran 31 tests in 157.805s
OK
```

All 31 targeted tests passed (26 existing regression tests + 5 new behavioral tests).

---

## 4. Smokes and Delivery Integration Demo

1. **`scripts/smoke.sh`**:
   - Command: `TMPDIR=/tmp/opencode KEEP_SMOKE=1 bash scripts/smoke.sh`
   - Exit code: 0
   - Output: `SMOKE_OK`
   - Log: `/tmp/opencode/smoke.log`

2. **`scripts/smoke-turbo.sh`**:
   - Command: `TMPDIR=/tmp/opencode KEEP_SMOKE=1 bash scripts/smoke-turbo.sh`
   - Exit code: 0
   - Output: `SMOKE_TURBO_OK`
   - Log: `/tmp/opencode/smoke-turbo.log`

3. **`scripts/demo-delivery-integration.sh`**:
   - Command: `DEMO_KEEP_EVIDENCE_DIR=/tmp/opencode/issue-83-delivery-demo bash scripts/demo-delivery-integration.sh`
   - Exit code: 0
   - Output: `DEMO_DELIVERY_INTEGRATION_OK`
   - Summary: `/tmp/opencode/issue-83-delivery-demo/delivery-integration-summary.json` (`"success": true`)
   - Log: `/tmp/opencode/demo-delivery.log`

---

## 5. Diff Size & Hard Guardrails

Command: `git diff --numstat origin/main...HEAD`
```
64      25      factory/integration.py
45      0       tests/test_deliver_integration.py
200     0       tests/test_integration.py
```
Total counted diff: **334 lines** (within the 300–500 line estimate, well below the 1,000 hard limit).
