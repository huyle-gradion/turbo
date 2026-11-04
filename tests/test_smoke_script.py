import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import ROOT


class SmokeScriptTest(unittest.TestCase):
    def test_smoke_never_deletes_a_pre_existing_temp_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "tmpdir"
            sandbox.mkdir()
            pre_existing = sandbox / "factory-smoke"
            pre_existing.mkdir()
            sentinel = pre_existing / "precious.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            env = dict(os.environ, TMPDIR=str(sandbox))
            result = subprocess.run(
                ["sh", str(ROOT / "scripts" / "smoke.sh")],
                capture_output=True,
                text=True,
                env=env,
                timeout=600,
            )
            kept = sentinel.exists() and sentinel.read_text(encoding="utf-8") == "keep\n"
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-3000:])
        self.assertIn("SMOKE_OK", result.stdout)
        self.assertTrue(kept, "the smoke script must not delete a directory it did not create")


if __name__ == "__main__":
    unittest.main()
