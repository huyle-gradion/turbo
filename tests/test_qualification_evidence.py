"""Qualification evidence derives from observed outcomes (issue #96).

Offline only: provider calls are replaced by in-process fakes, and git runs only
against disposable local repositories.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import unquote, urlparse

from factory import qualification

ROOT = Path(__file__).resolve().parents[1]
SLUG = "turbo-factory/turbo-qual-67"
NOT_PASSING = ("failed", "unavailable")
SYNTHESIZED = (
    "Pull Request has merge conflicts",
    "At least 1 approving review is required",
    "You must have repository read permissions",
)


def _command_text(entry: dict) -> str:
    cmd = entry.get("command")
    return " ".join(map(str, cmd)) if isinstance(cmd, (list, tuple)) else str(cmd)


def _run_main(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return qualification.main(argv)


def _rejected_result() -> SimpleNamespace:
    return SimpleNamespace(
        status="rejected", outcome="rejected", mutation_outcome="rejected", landed_sha=None,
        tested_sha=None, reconciled=False, blockers=["forced-failure: test made this attempt fail"],
    )


@contextlib.contextmanager
def _hosted_fakes(*, failing: str | None = None, prep_blockers: list[str] = (), with_artifacts: bool = True,
                  artifactless: str | None = None):
    """Run hosted qualification through main() with preflight, preparation and scenarios faked."""
    def scenario(name: str):
        def run(base_url, repo_slug, evidence_dir, *args, **kwargs):
            arts = []
            if with_artifacts and name != artifactless:
                art = Path(evidence_dir) / "scenarios" / name / "scenario-result.json"
                art.parent.mkdir(parents=True, exist_ok=True)
                art.write_text("{}", encoding="utf-8")
                arts = [str(art)]
            res = {"name": name, "scenario": name, "outcome": "failed" if name == failing else "verified",
                   "status": "failed" if name == failing else "confirmed", "simulated": False,
                   "candidate_sha": "c" * 40, "base_sha": "b" * 40, "artifacts": arts, "blockers": []}
            return (res, "feat/qual-cand", "d" * 40, 9) if name == "competing_base_rejection" else res
        return run

    prep = {"status": "blocked" if prep_blockers else "prepared", "outcome": "unavailable" if prep_blockers else "prepared",
            "blockers": list(prep_blockers)}
    orig_hosted = qualification.run_hosted_qualification

    def hosted_test_origin(*a, **k):
        return orig_hosted(*a, **{**k, "allow_test_origin": True})

    q = "factory.qualification."
    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.dict(os.environ, {
            "TURBO_LIVE_QUALIFICATION": "1", "TURBO_QUAL_INTEGRATOR_TOKEN": "fake-int-tok",
            "TURBO_QUAL_COMPETITOR_TOKEN": "fake-comp-tok",
        }))
        st.enter_context(mock.patch(q + "run_hosted_qualification", hosted_test_origin))
        st.enter_context(mock.patch(q + "observe_identity_and_permissions", return_value=(True, {}, [])))
        st.enter_context(mock.patch(q + "check_branch_protection_and_topology", return_value=(True, {}, [])))
        st.enter_context(mock.patch(q + "check_seed_and_workflow_capabilities", return_value=(True, {}, [])))
        st.enter_context(mock.patch(q + "prepare_qualification_candidate", return_value=prep))
        st.enter_context(mock.patch("support_deliver.setup_disposable_delivery_context",
                                    lambda root: contextlib.nullcontext(SimpleNamespace(repo=Path(root)))))
        for fn, name in (("run_scenario_1_confirmed_landing", "confirmed_landing"),
                         ("run_scenario_2_prereq_missing_and_denied", "prereq_missing_and_denied"),
                         ("run_scenario_3_competing_base_rejection", "competing_base_rejection"),
                         ("run_scenario_4_renewed_verification_after_base_change", "renewed_verification_after_base_change")):
            st.enter_context(mock.patch(q + fn, scenario(name)))
        yield


class EvidenceIndexOutcomeTest(unittest.TestCase):
    def _load(self, ev: Path) -> tuple[dict, dict]:
        index = json.loads((ev / "parent-evidence-index.json").read_text(encoding="utf-8"))
        summary = json.loads((ev / "qualification-summary.json").read_text(encoding="utf-8"))
        return index, summary

    def test_index_records_real_command_exit_and_mode_of_a_failing_run(self) -> None:
        """AC1/AC2: a failed scenario yields a `failed` entry carrying the run's real command and non-zero exit."""
        import support_deliver  # noqa: F401  (patch target must be importable)

        real_integrate = qualification.integrate_approved_child
        calls: list[int] = []

        def first_attempt_fails(*a, **k):
            calls.append(1)
            return _rejected_result() if len(calls) == 1 else real_integrate(*a, **k)

        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp) / "ev-offline"
            with self.subTest(mode="offline"), mock.patch("factory.qualification.integrate_approved_child", first_attempt_fails):
                rc = _run_main(["--mode", "offline", "--evidence-dir", str(ev)])
                index, summary = self._load(ev)
                self.assertNotEqual(rc, 0, "a failed confirmed-landing scenario must fail the offline command")
                for ac in ("AC1", "AC5"):  # both include confirmed_landing
                    entry = index[ac]
                    self.assertEqual(entry["outcome"], "failed", ac)
                    self.assertEqual(entry["exit_status"], rc, ac)
                    self.assertIn("--mode offline", _command_text(entry), ac)
                    self.assertIn(str(ev), _command_text(entry), f"{ac}: command is not the actual argv")
                    self.assertIn("offline", entry["mode"], ac)
                    self.assertNotIn("hosted", entry["mode"], ac)
                self.assertIn(summary["outcome"], NOT_PASSING)

            variants = {
                "failed-scenario": dict(failing="prereq_missing_and_denied"),
                "preparation-blocker": dict(prep_blockers=["ci-poll-timeout: required check never completed"]),
                "empty-artifacts": dict(with_artifacts=False),
                "mixed-artifacts": dict(artifactless="prereq_missing_and_denied"),
            }
            for label, kw in variants.items():
                ev = Path(tmp) / f"ev-hosted-{label}"
                with self.subTest(mode="hosted", variant=label), _hosted_fakes(**kw):
                    rc = _run_main(["--mode", "hosted", "--evidence-dir", str(ev)])
                    index, summary = self._load(ev)
                    self.assertNotEqual(rc, 0)
                    self.assertFalse(summary["qualified"])
                    self.assertIn(summary["outcome"], NOT_PASSING, f"{label}: summary claims {summary['outcome']!r}")
                    for ac, entry in index.items():
                        self.assertEqual(entry["exit_status"], rc, ac)
                        self.assertIn("--mode hosted", _command_text(entry), ac)
                        self.assertEqual(entry["mode"], "hosted", ac)
                    if label == "failed-scenario":
                        self.assertEqual(index["AC1"]["outcome"], "failed")
                        self.assertEqual(index["AC4"]["outcome"], "failed")
                    elif label == "mixed-artifacts":  # AC1 = confirmed_landing (artifact) + prereq (none)
                        self.assertIn(index["AC1"]["outcome"], NOT_PASSING, f"AC1 claims {index['AC1']['outcome']!r}")
                    else:  # a run-wide blocker, or AC5's only scenario without artifacts
                        self.assertIn(index["AC5"]["outcome"], NOT_PASSING, f"{label}: AC5 claims {index['AC5']['outcome']!r}")
                    if label == "preparation-blocker":
                        self.assertIn(kw["prep_blockers"][0], summary["blockers"])

            # Reruns into the same evidence directory must not leave an earlier run's claims behind.
            ev = Path(tmp) / "ev-rerun"
            with self.subTest(rerun="passing-offline"):
                rc = _run_main(["--mode", "offline", "--evidence-dir", str(ev)])
                self.assertEqual(rc, 0, "a fully passing offline run must exit 0")
                self.assertEqual(self._load(ev)[1]["exit_status"], 0)
            ev_raise = Path(tmp) / "ev-rerun-raise"
            shutil.copytree(ev, ev_raise)
            with self.subTest(rerun="then-blocked-hosted"), mock.patch.dict(os.environ):
                for k in [k for k in os.environ if k.startswith(("TURBO_LIVE", "TURBO_QUAL"))]:
                    del os.environ[k]
                rc = _run_main(["--mode", "hosted", "--evidence-dir", str(ev)])
                self.assertNotEqual(rc, 0)
                self.assertEqual(self._persisted(ev)[0]["exit_status"], rc)
                for ac, entry in self._persisted(ev)[1].items():
                    self.assertEqual(entry.get("exit_status"), rc, f"stale {ac} index entry beside the hosted summary")
            with self.subTest(rerun="then-raising-offline"), \
                    mock.patch("factory.qualification.integrate_approved_child", side_effect=RuntimeError("forced crash")):
                with contextlib.suppress(Exception):
                    _run_main(["--mode", "offline", "--evidence-dir", str(ev_raise)])
                summary, index = self._persisted(ev_raise)
                for where, rec in [("summary", summary), *index.items()]:
                    if rec:
                        self.assertNotEqual(rec.get("exit_status"), 0, f"stale {where} claims exit 0")
                        out = str(rec.get("outcome"))
                        self.assertFalse("verified" in out or "passed" in out, f"stale {where} claims {out!r}")

    def _persisted(self, ev: Path) -> tuple[dict, dict]:
        """(summary, index) as persisted; an absent file reads as empty."""
        def read(name: str) -> dict:
            p = ev / name
            return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
        return read("qualification-summary.json"), read("parent-evidence-index.json")

    def test_reducer_never_passes_failed_missing_or_artifactless_outcomes(self) -> None:
        """AC2: the reducer reports failed/unavailable instead of trusting simulation or an empty artifact list."""
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "scenario-result.json"
            art.write_text("{}", encoding="utf-8")
            offline = {"status": "offline-simulated", "simulated": True}
            hosted = {"status": "verified", "simulated": False}
            cases = {
                "failed-simulated": (offline, {"s1": {"outcome": "failed", "simulated": True}}, [str(art)]),
                "failed-hosted": (hosted, {"s1": {"outcome": "failed", "simulated": False}}, [str(art)]),
                "missing-simulated": (offline, {}, [str(art)]),
                "missing-hosted": (hosted, {"s2": {"outcome": "verified", "simulated": False}}, [str(art)]),
                "no-artifacts-simulated": (offline, {"s1": {"outcome": "verified", "simulated": True}}, []),
                "no-artifacts-hosted": (hosted, {"s1": {"outcome": "verified", "simulated": False}}, []),
            }
            for label, preflight in (("mixed-artifacts-simulated", offline), ("mixed-artifacts-hosted", hosted)):
                with self.subTest(label):
                    sim = preflight is offline
                    index = {"AC1": {"ac_id": "AC1", "scenarios": ["s1", "artifactless_scenario"], "artifact_paths": [str(art)]}}
                    scenarios = {"s1": {"outcome": "verified", "simulated": sim, "artifacts": [str(art)]},
                                 "artifactless_scenario": {"outcome": "verified", "simulated": sim, "artifacts": []}}
                    reduced, qualified, blockers = qualification.reduce_evidence_index(index, preflight, scenarios)
                    self.assertFalse(qualified)
                    self.assertIn(reduced["AC1"]["outcome"], NOT_PASSING, label)
                    self.assertTrue(any("artifactless_scenario" in b for b in blockers), blockers)
            for label, (preflight, scenarios, arts) in cases.items():
                with self.subTest(label):
                    index = {"AC1": {"ac_id": "AC1", "scenarios": ["s1"], "artifact_paths": arts}}
                    reduced, qualified, _ = qualification.reduce_evidence_index(index, preflight, scenarios)
                    self.assertFalse(qualified)
                    self.assertIn(reduced["AC1"]["outcome"], NOT_PASSING, label)
                    if not arts:
                        self.assertNotEqual(reduced["AC1"]["subchecks"]["artifacts"], "verified")
                    if label.startswith("failed"):
                        self.assertEqual(reduced["AC1"]["outcome"], "failed")


_MAIN_READ = re.compile(r"/repos/[^/]+/[^/]+/(commits|branches|git/refs?)(/refs)?(/heads)?/main$")


class ProviderObservationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from support_deliver import setup_disposable_delivery_context
        cls._stack = contextlib.ExitStack()
        cls._tmp = Path(cls._stack.enter_context(tempfile.TemporaryDirectory()))
        (cls._tmp / "ws").mkdir()
        cls.ctx = cls._stack.enter_context(setup_disposable_delivery_context(cls._tmp / "ws"))
        from support import git
        git(cls.ctx.bare, "update-ref", "refs/heads/feature/demo", cls.ctx.base_sha)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stack.close()

    def test_main_preserved_compares_provider_main_before_and_after(self) -> None:
        """AC3: a provider whose `main` moves during the scenario yields main_preserved false."""
        real_http = qualification._http_req
        for label, provider in (("prereq_missing_and_denied", "moves"), ("competing_base_rejection", "moves"),
                                ("prereq_missing_and_denied", "read-fails")):
            reads: list[str] = []

            def moving_main(method, url, *a, provider=provider, reads=reads, **k):
                if method == "GET" and _MAIN_READ.search(unquote(urlparse(url).path)):
                    if provider == "read-fails":
                        reads.append("")
                        return 503, {}, ""
                    sha = "a" * 40 if not reads else "e" * 40
                    reads.append(sha)
                    return 200, {"sha": sha, "commit": {"sha": sha}, "object": {"sha": sha, "type": "commit"},
                                 "name": "main", "ref": "refs/heads/main"}, ""
                return real_http(method, url, *a, **k)

            ev = self._tmp / f"ev-ac3-{label}-{provider}"
            with self.subTest(label, provider=provider), mock.patch("factory.qualification._http_req", moving_main):
                args = (self.ctx.gh.base_url, SLUG, ev, self.ctx, "disp-tok", "comp-tok")
                if label == "prereq_missing_and_denied":
                    sc = qualification.run_scenario_2_prereq_missing_and_denied(*args, allow_test_origin=True)
                else:
                    sc = qualification.run_scenario_3_competing_base_rejection(*args, allow_test_origin=True)[0]
                self.assertGreaterEqual(len(reads), 2, "remote main was not read from the provider before and after")
                self.assertIs(sc["main_preserved"], None if provider == "read-fails" else False)
                self.assertEqual(sc["outcome"], "failed")

    def test_provider_messages_are_verbatim_or_null(self) -> None:
        """AC4: an empty provider response body never turns into invented provider text."""
        denied = SimpleNamespace(status="denied", outcome="denied", mutation_outcome="denied", landed_sha=None,
                                 tested_sha=None, reconciled=False, blockers=[])
        ev = self._tmp / "ev-ac4"
        with mock.patch("factory.qualification._http_req", return_value=(403, {}, "")), \
                mock.patch("factory.qualification.fetch_remote_repo"), \
                mock.patch("factory.qualification.integrate_approved_child", return_value=denied):
            sc = qualification.run_scenario_2_prereq_missing_and_denied(
                "https://api.github.com", SLUG, ev, self.ctx, "fake-int-tok", "fake-comp-tok",
            )
        persisted = "\n".join(p.read_text(encoding="utf-8") for p in ev.rglob("*") if p.is_file())
        for literal in SYNTHESIZED:
            self.assertNotIn(literal, json.dumps(sc))
            self.assertNotIn(literal, persisted)
        source = Path(qualification.__file__).read_text(encoding="utf-8")
        for literal in SYNTHESIZED:
            self.assertFalse(literal in source, f"synthesized provider message {literal!r} in factory/qualification.py")


class QualificationScriptTest(unittest.TestCase):
    def test_script_keeps_evidence_after_failing_run(self) -> None:
        """AC5: without an explicit opt-in, the evidence directory survives a failing run."""
        with tempfile.TemporaryDirectory() as sandbox, tempfile.TemporaryDirectory() as shim:
            real_mktemp = subprocess.run(["sh", "-c", "command -v mktemp"], capture_output=True, text=True, check=True).stdout.strip()
            shim_path = Path(shim) / "mktemp"
            shim_path.write_text(
                "#!/bin/sh\n"
                'for a in "$@"; do last="$a"; done\n'
                'case "$last" in -*|"") last=tmp.XXXXXX ;; esac\n'
                f'exec "{real_mktemp}" -d "{sandbox}/${{last##*/}}"\n',
                encoding="utf-8",
            )
            shim_path.chmod(0o755)
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("TURBO_LIVE", "TURBO_QUAL", "DEMO_")) and k != "EVIDENCE"}
            env.update(TMPDIR=sandbox, PATH=f"{shim}{os.pathsep}{env.get('PATH', '')}")
            # Hosted mode without TURBO_LIVE_QUALIFICATION is blocked before any network access.
            proc = subprocess.run(
                ["bash", str(ROOT / "scripts" / "qualify-protected-demo.sh"), "--mode", "hosted"],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stderr)
            kept = [p for p in Path(sandbox).iterdir() if p.is_dir()]
            self.assertTrue(kept, f"evidence directory was deleted on exit; stderr: {proc.stderr[-500:]}")
            self.assertTrue(any((p / "qualification-summary.json").is_file() for p in kept))


if __name__ == "__main__":
    unittest.main()
