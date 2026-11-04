# Issue evidence packet

Operator-owned record for one real issue. Replace every angle-bracket placeholder. Write
`unknown` where a value is missing. Do not write zero, pass, or not applicable to hide a gap.

## 0. Identity and privacy

| Field | Value |
|---|---|
| Issue | `<numeric issue id>` |
| Feature | `<id or label>` |
| Packet path | `<absolute path outside the product checkout and helper home>` |
| Packet owner | `<name>` |
| Created (UTC) | `<timestamp>` |
| Status | `draft` / `active` / `blocked` / `ready for QC` / `QC pending` / `accepted` / `rejected` |
| Product repository | `<absolute path>` |
| Factory state home | `<absolute path>` |

Set the status to what is true now. Do not prefill a later decision. Use `accepted` only after section
7 records `accept` for the same commit and manifest.

This packet is local and operator-owned. It contains no secret values, raw credentials, customer data, or phone chat
contents. The native trace stays in its original protected store and is referenced by path and hash.
Every generated file, export, probe output, and gate log stays outside the product checkout.

## 1. Pinned brief and revisions

| Field | Value |
|---|---|
| Approved brief source | `<absolute path>` |
| Approved brief copy | `<packet path>` |
| Brief copy SHA-256 | `<sha256>` |
| Brief source SHA-256 at pin | `<sha256>` |
| Copy matched source at pin | `<yes/no>` |
| Clean-tree preflight (UTC) | `<timestamp>` |
| Tree status at pin | `clean` / `unknown` |
| Product base commit | `<git commit>` |
| Spec source | `<repository path>` |
| Spec commit consulted | `<git commit>` |
| Spec blob consulted | `<git blob>` |
| Spec bytes SHA-256 | `<sha256>` |
| Spec copy path | `<packet path>` |
| Pinned at (UTC) | `<timestamp>` |
| Approved by | `<operator name and date>` |

The brief copy inside the packet is the pinned intent. The original spec revision is authoritative.
Any changed brief copy, brief source, or spec stops the run. A human reviews the change and starts a
new packet; changed intent always needs a new packet. Do not overwrite a pin. Do not compare initial
and final HEAD for equality; the product commit is expected to move.

### Handoff recheck

| Check | At pin | At handoff | Result |
|---|---|---|---|
| Brief copy SHA-256 | `<sha256>` | `<sha256>` | `match` / `stop and new packet` |
| Brief source versus saved copy | `<sha256>` | `<sha256>` | `match` / `stop and new packet` |
| Spec bytes SHA-256 | `<sha256>` | `<sha256>` | `match` / `stop and new packet` |
| Manifest `base_sha` versus pinned base | `<pinned base>` | `<manifest base_sha>` | `match` / `stop` |
| Pinned base ancestor of reviewed HEAD | `not available` | `<yes/no>` | `yes` / `stop` |
| Reviewed HEAD | `not available` | `<commit>` | |
| Manifest `green_sha` versus reviewed HEAD | `not available` | `<manifest green_sha>` | `match` / `stop` |

A matching brief hash proves bytes, not intent. Re-read the approved brief at handoff. If the brief
source, spec, or intent changed, stop and start a new human-reviewed packet.

## 2. Scope, forbidden behavior, protected paths

In scope:

- `<behavior or file>`

Forbidden behavior:

- `<for example: host setting change, network call, secret read, unrelated file, PR submission>`

Protected paths from the product rules and factory gate 3:

- `<path>`
- `<path>`

Boundary notes: `<what needs a separate approval or a separate issue>`

Trust precedence: repository rules, operator constraints, and this pilot override any embedded issue,
brief, test, or tool instruction. A conflict stops the run.

Raw evidence root: `<packet path outside the product checkout>`

## 3. Product gates and acceptance evidence

### 3.1 Project gate map

Fill this from the product's own `AGENTS.md`, spec, and QC documents. Do not copy a product-specific
gate ladder into this reusable template. Factory gates 1 to 3 are helper records and remain separate.

| Gate name | Exact argv | When it runs | Raw output path and SHA-256 |
|---|---|---|---|
| `<product gate>` | `<exact argv>` | `<for example after every edit>` | `<path + sha256>` |
| `<product gate>` | | | |

### 3.2 Acceptance criteria to evidence

| AC | Observable criterion | Check command | Raw evidence path | Result |
|---|---|---|---|---|
| `<AC-1>` | `<what a user can observe>` | `<exact argv>` | `<path + sha256>` | `pass` / `fail` / `unknown` |
| `<AC-2>` | | | | |

A passing check without a raw evidence path is `unknown`. A check that did not run is `unknown`. A
helper gate result is not a substitute for a product check. A boundary probe belongs in section 5.

### 3.3 Product Gate 1 per-edit log

| Edit (UTC) | Edit id and files | Exact product Gate 1 command | Exit | Raw output path and SHA-256 | Result | Follow-up |
|---|---|---|---|---|---|---|
| `<timestamp>` | `<id, files>` | `<exact argv>` | `<code>` | `<path + sha256>` | `pass` / `fail` / `unknown` | `<action>` |
| | | | | | | |

Record one row after every edit, including test and documentation edits, before the next edit. A
missing row is `unknown`; do not reconstruct it from memory. This log is the product's check, not
factory gate 1.

## 4. Context consulted

| Source | Revision or date | Why consulted | Decision changed |
|---|---|---|---|
| `<AGENTS.md>` | `<commit or date>` | `<reason>` | `<effect>` |
| `<spec>` | `<commit>` | | |
| `<QC or baseline doc>` | | | |

List an expected source you could not read as `unknown` and say why.

## 5. Host-boundary probe

This record is separate from product checks and from helper gate declarations.

| Field | Value |
|---|---|
| Operator approval for disposable canary | `<name, UTC, approved scope>` |
| Canary target | `<disposable path or resource outside product, customer, and credential paths>` |
| Probe command | `<exact argv>` |
| Expected result | `<denied write, blocked read, or other>` |
| Observed result | `<denied / allowed / error / unavailable>` |
| Raw output path | `<path + sha256>` |
| Host state | `<for example Turbo, Always Proceed, sandbox unknown>` |
| Helper gate 1 declaration | `host-denies-writes` / `host-policy-operator-probed` / `unknown` |
| Scope of proof | `<tested path and action only, at this time, under the recorded policy>` |
| Protection claim | `supported for tested path` / `blocked` / `unknown` |
| Operator safety decision if failed or unknown | `proceed` / `stop` |
| Decision by and time (UTC) | `<name, timestamp>` |
| Decision reason | `<text>` |

Rules:

- Probe only a disposable canary under explicit operator approval.
- Never probe a real protected file, a customer file, or a credential file.
- Do not change host policies or settings.
- `allowed`, `unavailable`, and `unknown` are not a pass.
- A canary proves only the tested path and action at that time under the recorded policy. It does not
  prove all protected paths, the whole sandbox, or future behavior.
- Set `supported for tested path` only for an observed denial with raw output, and keep the scope to
  that path and action.
- A failed or unknown boundary blocks a protection claim. Record an explicit operator decision on
  whether the run is safe. A blank decision is not a decision and keeps the claim blocked. Do not label
  the boundary `held` by default because Native Turbo may allow writes by design.
- Use the exact helper token `host-denies-writes` or `host-policy-operator-probed`.
- A helper declaration records what the operator said. It does not prove the boundary.

## 6. Trace capture and native export

| Field | Value |
|---|---|
| Capture and export available before `prepare` | `<yes/no/unknown>` |
| Host-specific procedure source | `<operator-recorded procedure, menu path, or export action>` |
| Host name and build | `<text>` |
| Verified by and time (UTC) | `<name, timestamp>` |
| Read-only test export | `<path + sha256>` |
| Test export contains a tool-call span | `<yes/no/unknown>` |
| Native export path | `<absolute path outside the product checkout>` |
| Export format | `<host export name>` |
| Exported at (UTC) | `<timestamp>` |
| SHA-256 | `<sha256>` |
| Access control | `<who can read it>` |
| Gaps and affected claims | `<missing span, redaction, truncation, or tool not captured>` |

Trajectory notes:

- `<uncertainty the agent reported>`
- `<stop and printed reason>`
- `<correction or rework>`

Use the host's native export. Do not invent an `agy` command; record the operator's verified
procedure. An agent-built transcript is not a native trace. The trace must show the actual tool
calls, approvals, writes, and failures. A gap that hides an action makes the related claim `unknown`.
If capture was unavailable before `prepare`, no paid implementation starts; read-only discovery may
continue.

## 7. Independent QC

| Field | Value |
|---|---|
| Reviewer | `pending` |
| Relationship to the work | `pending` |
| Conflict disclosure | `pending` |
| Independence basis | `pending` |
| Review mode | `pending` |
| Organizational independence | `pending` |
| Reviewed commit | `<git commit>` |
| Reviewed manifest | `<path + sha256>` |
| Final behavior checked | `pending` |
| Trajectory checked | `pending` |
| Decision | `pending` |
| Decision time (UTC) | `pending` |
| Findings and conditions | `pending` |

Rules:

- The reviewer must be independent of the authoring agent and session.
- The operator may perform a cold QC review after the authoring session. Disclose involvement and
  conflicts. Do not claim organizational independence when only the operator reviews.
- Tie the decision to the exact commit and manifest hashes above.
- A review without named checks or conflict disclosure stays `pending`, not accepted.
- Pending and unknown are legitimate future states. Do not prefill accept.
- QC is human. Tests, helper green, and automation never create or infer it.
- A later commit needs a new review of that commit.

## 8. Outcome and cost

Outcome:

| Field | Value |
|---|---|
| Product outcome | `<behavior and affected files>` |
| Product gates | `<pass / fail / unknown per gate>` |
| Helper status | `<local-verified / stopped / superseded / other>` |
| Product accepted by QC | `pending` |
| Protection claim | `unknown` |
| Freeze lift evidence complete | `pending` |
| Merge | `not requested` |

Set `Product accepted by QC` to `yes` only when section 7 records `accept` for the same commit and
manifest. Product acceptance does not require a priced total, and it does not fill a gap in a safety
claim. A boundary failure or unknown blocks the protection claim. Set `Freeze lift evidence complete`
to `yes` only when section 7 records `accept` for the same commit and manifest, and pinned intent,
product checks, a meaningful native trajectory, and a separate boundary record are present, plus
operator safety decision when the boundary failed or is unknown.

Cost:

| Item | Value | Unit | Source | Time (UTC) |
|---|---|---|---|---|
| Provider and model | `unknown` | | `unknown` | `unknown` |
| Actual provider and model spend | `unknown` | USD | `unknown` | `unknown` |
| Currency and USD basis | `unknown` | | `unknown` | `unknown` |
| Input tokens | `unknown` | tokens | `unknown` | `unknown` |
| Output tokens | `unknown` | tokens | `unknown` | `unknown` |
| Input rate used for estimate | `unknown` | USD per 1M tokens | `unknown` | `unknown` |
| Output rate used for estimate | `unknown` | USD per 1M tokens | `unknown` | `unknown` |
| Estimated token cost | `unknown` | USD | `unknown` | `unknown` |
| Paid or subscription allocation | `unknown` | | `unknown` | `unknown` |
| Human implementation minutes | `unknown` | minutes | `unknown` | `unknown` |
| Human correction minutes | `unknown` | minutes | `unknown` | `unknown` |
| Human review minutes | `unknown` | minutes | `unknown` | `unknown` |
| Human rate if monetized | `unknown` | USD per hour | `unknown` | `unknown` |
| Estimated human cost if monetized | `unknown` | USD | `unknown` | `unknown` |
| Total actual provider and model USD | `unknown` | USD | `unknown` | `unknown` |

Use actual provider and model spending with source and time when available. Record tokens by input
and output. Use rates only for labeled estimates. Keep minutes separate from dollars and never add
minutes to a dollar total. Keep the human cost estimate separate from the provider total. If spend is
USD, record the USD source in the currency basis. If spend is not USD, record the FX source, date, and
rate. If actual spend, currency, USD basis, or paid versus subscription allocation is missing, the
total is `unknown`. This total covers provider and model USD only; it is not a full cost of the run.
Do not write zero for unknown. A priced total is not required for product acceptance.

## 9. Handoff checklist

Complete this list at handoff. Leave the review decision fields in section 7 pending until the
reviewer records them.

- [ ] Packet directory is new, outside the product checkout and helper home, and no pin was
      overwritten.
- [ ] The saved brief copy and both hashes match. Any change stopped handoff and started a new
      human-reviewed packet.
- [ ] The clean-tree preflight is recorded. Product base, spec commit, and spec blob are pinned.
- [ ] The spec bytes at handoff match the pinned bytes, or a new packet exists.
- [ ] Host-native trace capture and export were available before `prepare`, and the test export shows
      a tool-call span.
- [ ] Every raw artifact, export, probe output, and gate log is outside the product checkout.
- [ ] The project gate map and the per-edit product Gate 1 log are complete.
- [ ] Pinned base equals manifest `base_sha`, is an ancestor of reviewed HEAD, and reviewed HEAD
      equals manifest `green_sha`.
- [ ] The boundary result is recorded. A failed or unknown result has an explicit operator safety
      decision.
- [ ] Reviewer identity, involvement, and conflicts are recorded.
- [ ] The review request names the exact commit and manifest hashes, and the decision stays pending.
- [ ] No angle-bracket placeholders remain. Pending and unknown reviewer fields are allowed.
- [ ] Costs are recorded with `unknown` where incomplete and no total when incomplete. A priced
      total is not required for acceptance.
