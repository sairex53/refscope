#!/usr/bin/env python3
import hashlib
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev-storage.sh"
BINARY = ROOT / "build" / "refscope"


def digest(path):
    if not path.is_file():
        return None
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


class DevelopmentStorageTests(unittest.TestCase):
    def test_inventory_is_read_only_and_reports_ownership_classes(self):
        before = digest(BINARY)
        result = subprocess.run(
            [str(SCRIPT), "inventory"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("read-only", result.stdout)
        self.assertIn("PERMANENT", result.stdout)
        self.assertIn("REBUILDABLE", result.stdout)
        self.assertIn("EXTERNAL/SHARED", result.stdout)
        self.assertIn("UNKNOWN", result.stdout)
        self.assertEqual(digest(BINARY), before)

    def test_cleanup_default_is_dry_run(self):
        before = digest(BINARY)
        build_dir = ROOT / "build"
        result = subprocess.run(
            [str(SCRIPT), "clean-rebuildables"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("DRY RUN", result.stdout)
        self.assertTrue(build_dir.is_dir())
        self.assertEqual(digest(BINARY), before)

    def test_apply_requires_a_real_terminal(self):
        before = digest(BINARY)
        result = subprocess.run(
            [str(SCRIPT), "clean-rebuildables", "--apply"],
            cwd=ROOT,
            input="CLEAN REFSCOPE REBUILDABLES\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn("requires an interactive terminal", result.stdout)
        self.assertEqual(digest(BINARY), before)


if __name__ == "__main__":
    unittest.main()
