#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FACTORY="$ROOT/bin/factory"
tmpbase=${TMPDIR:-/tmp}
mkdir -p "$tmpbase"
base=$(mktemp -d "$tmpbase/factory-smoke.XXXXXX")
cleanup() {
    if [ "${KEEP_SMOKE:-0}" = "1" ]; then
        echo "smoke evidence kept at $base"
    else
        rm -rf "$base"
    fi
}
trap cleanup EXIT HUP INT TERM
repo="$base/repo"
home="$base/home"
mkdir -p "$repo"
git -C "$repo" init -q -b main
git -C "$repo" config user.email operator@example.test
git -C "$repo" config user.name Operator
git -C "$repo" config commit.gpgsign false
printf '# demo\n' > "$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -q -m base

"$FACTORY" --repo "$repo" --home "$home" init
"$FACTORY" --repo "$repo" --home "$home" configure --timezone UTC
"$FACTORY" --repo "$repo" --home "$home" configure --gate 1 --declare-host-deny -- python3 -c 'import sys; sys.exit(0)'
"$FACTORY" --repo "$repo" --home "$home" configure --gate 2 -- python3 -m unittest discover -s tests -p 'test_*.py' -q
"$FACTORY" --repo "$repo" --home "$home" configure --gate 3 --protected AGENTS.md --protected docs/spec.md --protected guards
"$FACTORY" --repo "$repo" --home "$home" spend record --usd 12.50 --source 'operator export 2026-11-03T09:00Z'
"$FACTORY" --repo "$repo" --home "$home" spend show
"$FACTORY" --repo "$repo" --home "$home" prepare --issue 7 --feature S-1 --kind feature --model synthetic-model --attest-model-account --time-limit 60m --operation-limit 40 --supervision-turns 40 --supervision-writes 50
git -C "$repo" switch -q -c run-issue-7
mkdir -p "$repo/tests"
printf 'def answer():\n    return 0\n' > "$repo/probe_impl.py"
printf 'import unittest\n\nfrom probe_impl import answer\n\n\nclass ProbeTest(unittest.TestCase):\n    def test_answer(self):\n        self.assertEqual(answer(), 42)\n' > "$repo/tests/test_probe.py"
printf '' > "$repo/tests/__init__.py"
git -C "$repo" add probe_impl.py tests
git -C "$repo" commit -q -m 'failing test'
"$FACTORY" --repo "$repo" --home "$home" red --issue 7 --test tests/test_probe.py --selector ProbeTest.test_answer --command "python3 -m unittest discover -s tests -p test_probe.py -v" --expect AssertionError
printf 'def answer():\n    return 42\n' > "$repo/probe_impl.py"
git -C "$repo" add probe_impl.py
git -C "$repo" commit -q -m implementation
sha=$(git -C "$repo" rev-parse HEAD)
"$FACTORY" --repo "$repo" --home "$home" stage --issue 7 --commit "$sha"
"$FACTORY" --repo "$repo" --home "$home" gate --issue 7 --gate 1
"$FACTORY" --repo "$repo" --home "$home" gate --issue 7 --gate 2
"$FACTORY" --repo "$repo" --home "$home" gate --issue 7 --gate 3
"$FACTORY" --repo "$repo" --home "$home" replay --issue 7
"$FACTORY" --repo "$repo" --home "$home" green --issue 7
"$FACTORY" --repo "$repo" --home "$home" manifest --issue 7
"$FACTORY" --repo "$repo" --home "$home" doctor
"$FACTORY" --repo "$repo" --home "$home" status --issue 7 --json
"$FACTORY" --repo "$repo" --home "$home" prompt --issue 7
"$FACTORY" --repo "$repo" --home "$home" resume --issue 7 --pr none
test -z "$(git -C "$repo" status --porcelain)"
test ! -e "$repo/.factory"
echo SMOKE_OK
