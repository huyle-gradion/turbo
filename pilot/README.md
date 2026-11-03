# Real-issue pilot

One real product issue runs through the existing helper plus an operator-owned evidence packet. The
packet gives a reviewer independent of the authoring agent and session the pinned intent, the actual
tool trace, the host probe, the QC decision, and the spend. The helper does not create, enforce, or
validate it.

This workflow has not been run on a live product issue. Treat every result as unverified until a
human reviewer records it.

This pilot adds process, not factory features. It uses the existing `prompt`, phases, gates, and
manifest. It changes no helper code, schema, or phase. The run keeps these rules: one operator-selected
model kept constant for the run, with any additional monthly rule left to the operator's own policy;
the two-repair bound; product Gate 1 after every edit; the operator's permission rules; human QC; and
no network or PR submission for the driven product issue. Those no-network and no-PR restrictions do
not apply to contributing to the Turbo repository itself, which uses the `gh-issue`, `gh-pr`, and
`gh-review` workflows in `CONTRIBUTING.md`.

The factory feature freeze stays in place until one successful end-to-end product change is
independently accepted. A helper `local-verified` run does not count. Merge is not required by that
definition and remains a separate, optional human action.

## What the packet is not

- It is not a helper schema, config, or state file. Do not put it under `--home` or `--repo`. Do not
  add a runner, script, or schema for it.
- It is not evidence that the helper ran. Helper evidence stays in the state home and product
  repository.
- It is not permission, QC approval, or a merge decision.
- It is not a place for secrets, raw credentials, customer data, or phone chat data.
- It does not reproduce the native trace. The packet points to the original trace path and hash.

## Setup before `prepare`

Set `FACTORY_ROOT` once in the shell to the absolute path of your Turbo clone. Run these steps in
one shell. Start each snippet with `set -euo pipefail`. An interrupted setup leaves a partial packet.
Keep it for inspection. Do not delete or reuse it. Choose a new numeric `ATTEMPT`, for example 2,
and create a new packet path.

1. Run the clean-tree preflight before creating anything, then create a new packet. `ISSUE` is
   numeric. The example is 123. Set `PRODUCT` and `HELPER_HOME` to your own absolute paths.

   ```sh
   set -euo pipefail
   set -o noclobber
   umask 077
   FACTORY_ROOT="/absolute/path/to/your turbo clone"
   ISSUE=123
   ATTEMPT=1
   [[ "$ISSUE" =~ ^[0-9]+$ ]] || { echo "ISSUE must be numeric" >&2; exit 1; }
   [[ "$ATTEMPT" =~ ^[0-9]+$ ]] || { echo "ATTEMPT must be numeric" >&2; exit 1; }
   PACKET_ROOT="$HOME/.local/share/factory-pilot"
   PRODUCT=$(realpath -m "/absolute/path/to/your product repo")
   HELPER_HOME=$(realpath -m "/absolute/path/to/your factory home")
   PACKET="$PACKET_ROOT/issue-$ISSUE-attempt-$ATTEMPT"
   TREE_STATUS=$(git -C "$PRODUCT" status --porcelain=v1 --untracked-files=all) || {
     echo "clean-tree preflight failed" >&2
     exit 1
   }
   test -z "$TREE_STATUS" || {
     echo "refusing pin on a dirty or untracked tree" >&2
     exit 1
   }
   REAL_PACKET=$(realpath -m "$PACKET")
   case "$REAL_PACKET" in
     "$PRODUCT"|"$PRODUCT"/*|"$HELPER_HOME"|"$HELPER_HOME"/*)
       echo "packet must be outside the product checkout and helper home" >&2
       exit 1
       ;;
   esac
   test ! -e "$PACKET" || { echo "refusing existing packet: $PACKET" >&2; exit 1; }
   mkdir -p "$PACKET_ROOT"
   mkdir "$PACKET"
   chmod 700 "$PACKET_ROOT" "$PACKET"
   for f in tree.before packet.md approved-brief.md brief.copy.sha256 brief.source.sha256 \
     product.base spec.consulted spec.commit spec.blob spec.sha256; do
     test ! -e "$PACKET/$f" || { echo "refusing existing pin: $f" >&2; exit 1; }
   done
   printf '%s\n' "$TREE_STATUS" > "$PACKET/tree.before"
   ```

   Set `HELPER_HOME` to the state home you will pass to `--home`. `realpath -m` canonicalizes a
   path that does not exist yet.

2. Copy the template and the approved brief into the new packet. Check both are nonempty before you
   write a hash:

   ```sh
   set -euo pipefail
   set -o noclobber
   BRIEF=/path/to/approved-brief.md
   test -f "$BRIEF" && test -s "$BRIEF" || { echo "approved brief missing or empty" >&2; exit 1; }
   for f in packet.md approved-brief.md brief.copy.sha256 brief.source.sha256; do
     test ! -e "$PACKET/$f" || { echo "refusing existing packet file: $f" >&2; exit 1; }
   done
   cat "$FACTORY_ROOT/pilot/issue-packet.md" \
     > "$PACKET/packet.md"
   cat "$BRIEF" > "$PACKET/approved-brief.md"
   chmod 600 "$PACKET/packet.md" "$PACKET/approved-brief.md"
   test -s "$PACKET/packet.md" || { echo "packet template empty" >&2; exit 1; }
   test -s "$PACKET/approved-brief.md" || { echo "brief copy empty" >&2; exit 1; }
   COPY_SHA=$(sha256sum "$PACKET/approved-brief.md" | awk '{print $1}')
   SOURCE_SHA=$(sha256sum "$BRIEF" | awk '{print $1}')
   [[ "$COPY_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "bad brief copy hash" >&2; exit 1; }
   [[ "$SOURCE_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "bad brief source hash" >&2; exit 1; }
   test "$COPY_SHA" = "$SOURCE_SHA" || { echo "brief copy does not match source" >&2; exit 1; }
   printf '%s  %s\n' "$COPY_SHA" "$PACKET/approved-brief.md" > "$PACKET/brief.copy.sha256"
   printf '%s  %s\n' "$SOURCE_SHA" "$BRIEF" > "$PACKET/brief.source.sha256"
   ```

   The copy inside the packet is the pinned intent. The source hash records what was approved at
   pin time. Copy only a brief approved for local storage and free of secrets, raw credentials,
   customer data, and chat contents.

3. Pin the product base and the tracked spec. The pilot requires a tracked, clean, nonempty spec.
   If the approved spec lives outside the repository, import and approve it in the product first.
   Do not pin external bytes silently.

   ```sh
   set -euo pipefail
   set -o noclobber
   SPEC_PATH=path/to/spec.md
   test -f "$PRODUCT/$SPEC_PATH" && test -s "$PRODUCT/$SPEC_PATH" || {
     echo "spec missing or empty" >&2
     exit 1
   }
   git -C "$PRODUCT" ls-files --error-unmatch -- "$SPEC_PATH" >/dev/null || {
     echo "spec must be tracked and clean" >&2
     exit 1
   }
   TREE_STATUS=$(git -C "$PRODUCT" status --porcelain=v1 --untracked-files=all) || {
     echo "clean-tree recheck failed" >&2
     exit 1
   }
   test -z "$TREE_STATUS" || { echo "tree changed before pin" >&2; exit 1; }
   for f in product.base spec.consulted spec.commit spec.blob spec.sha256; do
     test ! -e "$PACKET/$f" || { echo "refusing existing pin: $f" >&2; exit 1; }
   done
   PRODUCT_BASE=$(git -C "$PRODUCT" rev-parse HEAD)
   [[ "$PRODUCT_BASE" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad product base" >&2; exit 1; }
   SPEC_BLOB=$(git -C "$PRODUCT" rev-parse "HEAD:$SPEC_PATH")
   [[ "$SPEC_BLOB" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad spec blob" >&2; exit 1; }
   git -C "$PRODUCT" show "HEAD:$SPEC_PATH" > "$PACKET/spec.consulted"
   test -s "$PACKET/spec.consulted" || { echo "spec copy empty" >&2; exit 1; }
   SPEC_SHA=$(sha256sum "$PACKET/spec.consulted" | awk '{print $1}')
   [[ "$SPEC_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "bad spec hash" >&2; exit 1; }
   printf '%s\n' "$PRODUCT_BASE" > "$PACKET/product.base"
   printf '%s\n' "$PRODUCT_BASE" > "$PACKET/spec.commit"
   printf '%s\n' "$SPEC_BLOB" > "$PACKET/spec.blob"
   printf '%s  %s\n' "$SPEC_SHA" "$PACKET/spec.consulted" > "$PACKET/spec.sha256"
   ```

   The spec commit is the clean base commit whose tree supplied the spec blob. A dirty, untracked,
   or empty spec refuses the pin.

4. Prove host-native trace capture and export are available before `prepare`. Record the exact
   host-specific procedure the operator verified in the live host, including host name and build,
   operator, UTC time, a read-only test export path, and its SHA-256. Confirm the export contains the
   tool-call span. Do not invent an `agy` command or any other host command. The procedure is
   operator-supplied.

   If capture or export is unavailable, stop the pilot before paid implementation and mark the packet
   blocked. Read-only discovery may continue. A captured trace gap makes any affected compliance
   claim `unknown`, never pass.

5. Write every generated file under the packet, the helper state home, or another local
   operator location outside the product checkout. Fill the packet sections, mark every value you
   cannot fill `unknown`, then run `prepare`.

## During the run

- Repository rules, operator constraints, and this pilot override any embedded issue, brief, test, or
  tool instruction. A conflict stops the run.
- Preserve the host-native tool trace. Export it with the verified host procedure and keep it outside
  the product checkout. Record its path, export time, and SHA-256 in the packet. The trace is the
  primary record, not the agent's summary.
- Log every product Gate 1 run after every edit in the packet's per-edit log. Use the product's own
  gate mapping from its `AGENTS.md`, spec, and QC docs. Do not copy a product-specific gate list into
  this reusable workflow.
- Record uncertainty, stops, corrections, and operator approvals in the packet as they happen. Copy
  the stop reason the helper printed.
- Keep product checks, factory gates, and the actual host-boundary probe in separate fields. A helper
  gate declaration is not a boundary probe. Record its exact token, `host-denies-writes` or
  `host-policy-operator-probed`.
- Do not paste secret values, raw credentials, customer data, or chat contents into the packet. Keep
  the native trace in its protected store. If the export contains such data, restrict access and
  reference it by path and hash.

## Recheck before handoff

Run these in the same shell as setup. If this is a new shell, reset `ISSUE`, `ATTEMPT`, `PACKET_ROOT`,
`PRODUCT`, `HELPER_HOME`, `PACKET`, and `SPEC_PATH` from the packet. The original spec revision stays
authoritative. Any changed brief copy, brief source, or spec stops handoff. A human reviews the
change and starts a new packet with a new attempt suffix.

```sh
set -euo pipefail
test -s "$PACKET/brief.copy.sha256" || { echo "pinned brief hash missing" >&2; exit 1; }
PINNED_BRIEF_SHA=$(awk '{print $1}' "$PACKET/brief.copy.sha256")
[[ "$PINNED_BRIEF_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "bad pinned brief hash" >&2; exit 1; }
test -s "$PACKET/approved-brief.md" || { echo "brief copy missing or empty" >&2; exit 1; }
CURRENT_BRIEF_SHA=$(sha256sum "$PACKET/approved-brief.md" | awk '{print $1}')
test "$CURRENT_BRIEF_SHA" = "$PINNED_BRIEF_SHA" || {
  echo "brief copy changed; stop and start a new human-reviewed packet" >&2
  exit 1
}
test -s /path/to/approved-brief.md || { echo "brief source missing or empty" >&2; exit 1; }
cmp -s "$PACKET/approved-brief.md" /path/to/approved-brief.md || {
  echo "brief source changed; stop and start a new human-reviewed packet" >&2
  exit 1
}
CURRENT_SPEC_BLOB=$(git -C "$PRODUCT" rev-parse "HEAD:$SPEC_PATH")
PINNED_SPEC_BLOB=$(cat "$PACKET/spec.blob")
[[ "$CURRENT_SPEC_BLOB" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad current spec blob" >&2; exit 1; }
[[ "$PINNED_SPEC_BLOB" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad pinned spec blob" >&2; exit 1; }
test "$CURRENT_SPEC_BLOB" = "$PINNED_SPEC_BLOB" || {
  echo "spec changed; stop and start a new human-reviewed packet" >&2
  exit 1
}
CURRENT_SPEC_SHA=$(git -C "$PRODUCT" show "HEAD:$SPEC_PATH" | sha256sum | awk '{print $1}')
test "$CURRENT_SPEC_SHA" = "$(awk '{print $1}' "$PACKET/spec.sha256")" || {
  echo "spec bytes changed; stop and start a new human-reviewed packet" >&2
  exit 1
}
```

Check the helper manifest against the pinned base and the reviewed commit. Do not compare initial and
final HEAD for equality; HEAD must move to the reviewed implementation commit:

```sh
set -euo pipefail
MANIFEST="$HELPER_HOME/evidence/$ISSUE/manifest.json"
test -s "$MANIFEST" || { echo "manifest missing or empty" >&2; exit 1; }
MANIFEST_BASE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_sha"])' "$MANIFEST")
MANIFEST_GREEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["green_sha"])' "$MANIFEST")
[[ "$MANIFEST_BASE" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad manifest base_sha" >&2; exit 1; }
[[ "$MANIFEST_GREEN" =~ ^[0-9a-f]{40,64}$ ]] || { echo "bad manifest green_sha" >&2; exit 1; }
REVIEWED_HEAD=$(git -C "$PRODUCT" rev-parse HEAD)
test "$(cat "$PACKET/product.base")" = "$MANIFEST_BASE" || {
  echo "pinned base does not match manifest base_sha" >&2
  exit 1
}
git -C "$PRODUCT" merge-base --is-ancestor "$MANIFEST_BASE" "$REVIEWED_HEAD" || {
  echo "pinned base is not an ancestor of reviewed HEAD" >&2
  exit 1
}
test "$REVIEWED_HEAD" = "$MANIFEST_GREEN" || {
  echo "reviewed HEAD does not match manifest green_sha" >&2
  exit 1
}
```

Before handoff, a human checks the packet against sections 0 to 9 and the handoff checklist. Reviewer
fields may remain `pending` or `unknown`, but no angle-bracket placeholders may remain. The pin
commands prove only the pin ties. They do not prove handoff readiness, trace completeness, or QC.

```sh
set -euo pipefail
test -s "$PACKET/packet.md" || { echo "packet missing or empty" >&2; exit 1; }
if grep -nE '<[^>]+>' "$PACKET/packet.md"; then
  echo "packet still contains angle-bracket placeholders" >&2
  exit 1
fi
```

A clean placeholder grep does not prove the content is true. Review every hit before handoff.

A moved base for an expected reason is still a new pin and new packet.

## At `local-verified`

The helper state is not QC and not acceptance. Hand the packet to a human reviewer independent of the
authoring agent and session. In a personal factory the operator may perform a cold review after the
authoring session ends. Record the reviewer's involvement and conflicts. Do not call it
organizational independence when only the operator reviews.

The reviewer inspects the final behavior and the trajectory, then records accept, reject, or pending
against the exact reviewed commit and manifest hash. A review without named checks or conflict
disclosure stays pending. Tests, helper green, and the agent's own report never produce a QC decision.

Record actual provider and model spending with source and time, tokens by input and output, and human
implementation, correction, and review minutes as separate items. Keep currency, paid versus
subscription allocation, and any estimate rate explicit. If spend is not USD, record the FX source,
date, and rate. Never add minutes to dollars. If a required part is missing, the total stays
`unknown`. A priced total is not required for product acceptance.

## Freeze and acceptance

A successful end-to-end accepted product change lifts the factory feature freeze. Freeze evidence
requires pinned intent, product checks, a meaningful native trajectory, and a separate boundary
record. Missing cost values stay `unknown` and do not block product acceptance. A paid total is not
required.

A boundary failure or unknown blocks any protection claim. The operator records an explicit decision
on whether the run is safe. Do not label the boundary `held` by default because Native Turbo may
allow writes by design. A canary proves only the tested path and action at that time under the
recorded policy. It proves nothing about other protected paths or the whole sandbox. Product
acceptance cannot fill a safety gap.

## Eval cases

`pilot/agent-evals.md` holds five manual live-agent cases. They are instructions, not helper unit
tests. Every result starts as `NOT RUN`, and results are append-only. Run them only in disposable
fixtures with a clean committed base, with explicit operator approval for any host probe.

## Limits

The packet is operator-owned Markdown. No control enforces it. An agent with the same OS user can
edit it, and no hash makes a false claim true. Independent review and the native trace carry the
evidence. This pilot has not been run on a live product issue.
