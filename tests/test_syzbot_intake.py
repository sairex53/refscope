#!/usr/bin/env python3
"""Fixture coverage for offline syzbot intake and environment validation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from syzbot.intake import import_case, main  # noqa: E402


def build_id(path: Path) -> str:
    result = subprocess.run(["readelf", "-n", str(path)], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        if "Build ID:" in line:
            return line.split("Build ID:", 1)[1].strip().lower()
    raise AssertionError("fixture ELF has no build ID")


class IntakeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="refscope-syzbot-")
        self.root = Path(self.temp.name)
        self.report_dir = self.root / "prepared"
        self.report_dir.mkdir()
        self.tree = self.root / "kernel"
        self.tree.mkdir()
        subprocess.run(["git", "init", "-q", str(self.tree)], check=True)
        subprocess.run(["git", "-C", str(self.tree), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.tree), "config", "user.name", "Fixture"], check=True)
        (self.tree / "README.fixture").write_text("fixture tree\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.tree), "add", "README.fixture"], check=True)
        subprocess.run(["git", "-C", str(self.tree), "commit", "-qm", "fixture kernel"], check=True)
        self.commit = subprocess.run(["git", "-C", str(self.tree), "rev-parse", "HEAD"],
                                     capture_output=True, text=True, check=True).stdout.strip()
        (self.report_dir / ".config").write_text("CONFIG_KASAN=y\n# CONFIG_KMSAN is not set\n", encoding="utf-8")
        (self.report_dir / "repro.syz").write_text("syz program fixture\n", encoding="utf-8")
        (self.report_dir / "repro.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (self.report_dir / "crash.log").write_text("synthetic fixture crash log\n", encoding="utf-8")
        (self.report_dir / "bisection.txt").write_text("fixture bisection: not a real result\n", encoding="utf-8")
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        runner = self.bin_dir / "syz-execprog"
        self.runner_marker = self.root / "runner-was-executed"
        runner.write_text(f"#!/bin/sh\nprintf called > {self.runner_marker}\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
        vmlinux_source = self.root / "synthetic-vmlinux.c"
        vmlinux_source.write_text(
            "__attribute__((noinline,used)) void _stext(void) {}\n"
            "__attribute__((noinline,used)) void _etext(void) {}\n"
            "int main(void) { _stext(); _etext(); return 0; }\n",
            encoding="utf-8",
        )
        self.vmlinux = self.root / "synthetic-vmlinux"
        subprocess.run([os.environ.get("CC", "cc"), "-g", "-O0", "-Wl,--build-id=sha1",
                        str(vmlinux_source), "-o", str(self.vmlinux)], check=True)
        self.case_data = {
            "schema_version": 1,
            "bug_id": "fixture-2026-01",
            "title": "Synthetic fixture report (not a real bug)",
            "report_url": "https://syzkaller.appspot.com/bug?id=fixture",
            "kernel_commit": self.commit,
            "kernel_release": "fixture-kernel",
            "architecture": "amd64" if platform.machine().lower() == "x86_64" else platform.machine(),
            "compiler": "fixture compiler",
            "config_provenance": "test fixture generated locally",
            "vmlinux_build_id": build_id(self.vmlinux),
            "artifacts": {"config": ".config", "syz_reproducer": "repro.syz",
                          "c_reproducer": "repro.c", "original_log": "crash.log",
                          "bisection": "bisection.txt"},
            "bisection_information": "fixture bisection details",
            "sanitizer_configuration": {"KASAN": "enabled"},
        }
        self.write_report()

    def tearDown(self):
        self.temp.cleanup()

    def write_report(self):
        (self.report_dir / "report.json").write_text(json.dumps(self.case_data), encoding="utf-8")

    def invoke(self, *, vmlinux=None, kernel_tree=None, path_env=None):
        return import_case(
            str(self.report_dir), cases_dir=str(self.root / "cases"),
            kernel_tree=str(kernel_tree or self.tree),
            vmlinux=str(vmlinux or self.vmlinux),
            config_provenance="fixture config source",
            host_architecture=platform.machine(),
            path_env=str(path_env or self.bin_dir),
            effective_uid=0,
        )

    def test_full_valid_report_creates_case_layout_and_text_report(self):
        case_dir, result = self.invoke()
        self.assertTrue(result["valid"], result["errors"])
        for relative in ("README.md", "input/metadata.json", "input/.config", "input/repro.syz",
                         "input/repro.c", "input/crash.log", "input/bisection.txt",
                         "input/original-report.json", "case.json", "validation/result.json",
                         "validation/report.txt"):
            self.assertTrue((case_dir / relative).is_file(), relative)
        imported = json.loads((case_dir / "input/original-report.json").read_text(encoding="utf-8"))
        self.assertEqual(imported["kernel_commit"], self.commit)
        self.assertEqual((case_dir / "input/bisection.txt").read_text(), "fixture bisection: not a real result\n")
        self.assertFalse(result["reproduction_started"])
        self.assertFalse(self.runner_marker.exists(), "intake must not execute syz reproducers")
        self.assertIn("Environment validation: VALID", (case_dir / "validation/report.txt").read_text())
        self.assertEqual(result["sanitizer_configuration"]["CONFIG_KASAN"], "y")

    def test_local_json_report_file_import(self):
        case_dir, result = import_case(
            str(self.report_dir / "report.json"), cases_dir=str(self.root / "file-cases"),
            kernel_tree=str(self.tree), vmlinux=str(self.vmlinux),
            config_provenance="fixture config source", host_architecture=platform.machine(),
            path_env=str(self.bin_dir), effective_uid=0,
        )
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue((case_dir / "input/original-report.json").is_file())

    def test_missing_config_blocks(self):
        (self.report_dir / ".config").unlink()
        _, result = self.invoke()
        self.assertFalse(result["valid"])
        self.assertIn("kernel .config is missing", result["errors"])
        self.assertIsNone(result["config_hash"])

    def test_missing_vmlinux_blocks(self):
        _, result = self.invoke(vmlinux=self.root / "absent-vmlinux")
        self.assertFalse(result["valid"])
        self.assertTrue(any("vmlinux does not exist" in error for error in result["errors"]))

    def test_wrong_kernel_commit_blocks(self):
        self.case_data["kernel_commit"] = "0" * 40
        self.write_report()
        _, result = self.invoke()
        self.assertFalse(result["valid"])
        self.assertTrue(any("kernel tree commit mismatch" in error for error in result["errors"]))

    def test_wrong_architecture_blocks(self):
        self.case_data["architecture"] = "aarch64" if platform.machine().lower() == "x86_64" else "x86_64"
        self.write_report()
        _, result = self.invoke()
        self.assertFalse(result["valid"])
        self.assertTrue(any("architecture mismatch" in error for error in result["errors"]))

    def test_mismatched_build_id_blocks(self):
        self.case_data["vmlinux_build_id"] = "0" * 40
        self.write_report()
        _, result = self.invoke()
        self.assertFalse(result["valid"])
        self.assertTrue(any("vmlinux build ID mismatch" in error for error in result["errors"]))

    def test_absent_reproducer_blocks(self):
        (self.report_dir / "repro.syz").unlink()
        (self.report_dir / "repro.c").unlink()
        self.case_data["artifacts"] = {"config": ".config"}
        self.write_report()
        _, result = self.invoke()
        self.assertFalse(result["valid"])
        self.assertIn("syz/C reproducer is absent", result["errors"])

    def test_malformed_report_rejected_without_case_directory(self):
        malformed = self.root / "bad.json"
        malformed.write_text("{not json", encoding="utf-8")
        result = main([str(malformed), "--cases-dir", str(self.root / "cases")])
        self.assertEqual(result, 2)
        self.assertFalse((self.root / "cases").exists())

    def test_unknown_optional_fields_preserved(self):
        self.case_data["future_extension"] = {"opaque": [1, 2, 3]}
        self.write_report()
        case_dir, result = self.invoke()
        self.assertTrue(result["valid"], result["errors"])
        saved = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["extra_fields"]["future_extension"], {"opaque": [1, 2, 3]})

    def test_bug_id_placeholder_does_not_fetch_or_invent_report(self):
        case_dir = self.root / "id-cases"
        status, output = self.capture_cli(["SyzBot:fixture-77", "--cases-dir", str(case_dir)])
        self.assertEqual(status, 1)
        parsed = json.loads(output)
        self.assertEqual(parsed["case"]["title"], None)
        self.assertFalse(parsed["validation"]["valid"])
        self.assertFalse(parsed["validation"]["reproduction_started"])

    def capture_cli(self, args):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main([*args, "--format", "json"])
        return status, stdout.getvalue()


if __name__ == "__main__":
    unittest.main(verbosity=2)
