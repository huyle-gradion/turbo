import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = (
    ROOT / "skills" / "run-issue" / "SKILL.md",
    ROOT / "skills" / "run-issue-turbo" / "SKILL.md",
)
PUBLIC_DOCS = tuple(sorted({
    ROOT / "LICENSE",
    *ROOT.glob("*.md"),
    *ROOT.glob(".github/**/*.md"),
    *ROOT.glob("pilot/*.md"),
    *ROOT.glob("skills/*/SKILL.md"),
}, key=str))
PRIVATE_MARKERS = (
    "/home/",
    "/Users/",
    "/tmp/",
)
SESSION_ID = re.compile(r"\bses_[A-Za-z0-9]{8,}")


def frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if match is None:
        return {}
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


class BundleTest(unittest.TestCase):
    def test_manual_skill_has_parseable_frontmatter(self):
        text = SKILLS[0].read_text(encoding="utf-8")
        fields = frontmatter(text)
        self.assertEqual(fields.get("name"), "run-issue")
        self.assertTrue(fields.get("description"))
        self.assertIn("issue", fields["description"].lower())

    def test_turbo_skill_has_parseable_frontmatter(self):
        text = SKILLS[1].read_text(encoding="utf-8")
        fields = frontmatter(text)
        self.assertEqual(fields.get("name"), "run-issue-turbo")
        self.assertTrue(fields.get("description"))
        self.assertIn("turbo", fields["description"].lower())

    def test_readme_and_launcher_are_present(self):
        self.assertTrue((ROOT / "README.md").is_file())
        self.assertTrue((ROOT / "bin" / "factory").is_file())

    def test_phases_stop_at_local_verified(self):
        from factory.model import PHASES

        self.assertIn("local-verified", PHASES)
        self.assertNotIn("pr-open", PHASES)
        self.assertNotIn("accepted", PHASES)

    def test_skills_resolve_the_launcher_from_a_user_supplied_root(self):
        for skill in SKILLS:
            text = skill.read_text(encoding="utf-8")
            self.assertIn('FACTORY_ROOT="', text, skill)
            self.assertIn('FACTORY="$FACTORY_ROOT/bin/factory"', text, skill)
            self.assertIn('"$FACTORY_ROOT/README.md"', text, skill)

    def test_public_docs_do_not_hardcode_a_checkout_location(self):
        for path in PUBLIC_DOCS:
            text = path.read_text(encoding="utf-8")
            for marker in PRIVATE_MARKERS:
                self.assertNotIn(marker, text, f"{path} still contains {marker}")
            self.assertIsNone(SESSION_ID.search(text), f"{path} still contains a session id")

    def test_release_metadata_agrees(self):
        from factory import __version__ as package_version

        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(version, "0.2.0")
        self.assertEqual(package_version, version)
        self.assertIn(f"[{version}]", changelog)
        self.assertIn(version, readme)
        self.assertIn("MIT", readme)
        self.assertIn("Semantic Versioning", readme)

    def test_launcher_runs_from_a_relocated_bundle_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            clone = base / "turbo clone"
            (clone / "bin").mkdir(parents=True)
            shutil.copytree(
                ROOT / "factory",
                clone / "factory",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            launcher = clone / "bin" / "factory"
            shutil.copy2(ROOT / "bin" / "factory", launcher)
            os.chmod(launcher, 0o755)
            cwd = base / "unrelated working directory"
            cwd.mkdir()
            result = subprocess.run(
                [str(launcher), "--help"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("prepare", result.stdout)
        self.assertIn("configure", result.stdout)


if __name__ == "__main__":
    unittest.main()
