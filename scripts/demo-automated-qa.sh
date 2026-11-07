#!/usr/bin/env bash
# Offline demonstration of Issue #21: seeded behavioral failure -> stable QA finding ->
# orchestrator routing to builder without hand edits -> #20 CI gate + QA re-verification.
set -euo pipefail

FACTORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$FACTORY_ROOT/tests:$FACTORY_ROOT"
export PYTHONDONTWRITEBYTECODE=1

python3 - <<'PY'
from dataclasses import asdict
import json, os, subprocess, sys, tempfile
from pathlib import Path
from automated_qa.test_automated_qa import DEMO_REPAIR_BUILDER_SCRIPT, WHITESPACE_QA_CASE, _SyncGitHubServer
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from test_intake import _DisposableAsanaServer

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    repo, home, bare = _make_disposable_product_workspace(root)
    fake_agy = _make_fake_agy(root, "fake-demo-agy", DEMO_REPAIR_BUILDER_SCRIPT)
    cases_path = root / "qa-cases.json"
    cases_path.write_text(json.dumps({"cases": [asdict(WHITESPACE_QA_CASE)]}, indent=2), encoding="utf-8")
    with _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana, _SyncGitHubServer(bare_repo=bare) as gh:
        env = {
            **dict(os.environ),
            "TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "disposable-asana-token",
            "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "disposable-gh-token",
        }
        cmd = [
            sys.executable, "-m", "factory.automated_qa", "--repo", str(repo), "--home", str(home),
            "--task", "900", "--agy-bin", str(fake_agy), "--qa-cases-file", str(cases_path),
            "--max-correction-attempts", "2", "--time-limit", "60s", "--json",
        ]
        payload = json.loads(subprocess.run(cmd, capture_output=True, text=True, env=env, check=True).stdout)
        f0 = payload["findings"][0]
        assert payload["status"] == "qa-verified" and payload["qa_verified"] is True, payload
        assert payload["merged"] is False and payload["parent_accepted"] is False, payload
        assert f0["finding_id"] == "QA-101-AC-1-QA-AC-1-WHITESPACE" and f0["status"] == "resolved", f0
        print(json.dumps({
            "demo": "automated-qa-failure-to-correction-loop", "status": payload["status"],
            "qa_verified": payload["qa_verified"], "merged": payload["merged"], "parent_accepted": payload["parent_accepted"],
            "parent_acceptance_status": payload["parent_acceptance"]["parent_acceptance_status"],
            "round_1_sha": payload["qa_rounds"][0]["candidate_sha"], "round_1_status": payload["qa_rounds"][0]["status"],
            "round_2_sha": payload["qa_rounds"][1]["candidate_sha"], "round_2_status": payload["qa_rounds"][1]["status"],
            "finding_id": f0["finding_id"], "finding_status": f0["status"],
            "correction_attempts_used": payload["correction_attempts_used"],
        }, indent=2, sort_keys=True))
PY
