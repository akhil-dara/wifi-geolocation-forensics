"""
Evidence packaging and self-verification.

The package is the deliverable — the thing handed to another lab, an opposing
expert or a court. Everything here is about it being checkable by someone who
has only the ZIP and no copy of this tool, on a machine that is not this one.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from wifigeo.evidence import Case


class Packaging(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.case = Case(self.root, examiner="A. Examiner",
                         organisation="Example Forensics Ltd",
                         reference="TEST-001")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _package(self):
        return self.case.package({"ok": True, "case_id": self.case.case_id})

    def test_package_verifies_from_a_clean_extract(self):
        pkg = self._package()
        out = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(pkg["zip_path"]) as zf:
                zf.extractall(out)
            case_dir = os.path.join(out, self.case.case_id)
            proc = subprocess.run(
                [sys.executable, os.path.join(case_dir, "verify_evidence.py")],
                cwd=case_dir, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             "verifier failed:\n%s%s" % (proc.stdout, proc.stderr))
            self.assertIn("INTACT", proc.stdout)
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_tampering_is_detected(self):
        # The whole point. If a modified exhibit still verifies, the package
        # proves nothing.
        pkg = self._package()
        out = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(pkg["zip_path"]) as zf:
                zf.extractall(out)
            case_dir = os.path.join(out, self.case.case_id)
            target = os.path.join(case_dir, "case.json")
            with open(target, "a", encoding="utf-8") as fh:
                fh.write("\n")                       # one byte is enough
            proc = subprocess.run(
                [sys.executable, os.path.join(case_dir, "verify_evidence.py")],
                cwd=case_dir, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0,
                                "a modified package still verified")
            self.assertIn("MODIFIED", proc.stdout.upper() + proc.stderr.upper())
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_verifier_has_unix_line_endings(self):
        # The verifier carries a `#!/usr/bin/env python3` shebang. Written with
        # the platform default on Windows it gets CRLF endings, and a POSIX
        # recipient running ./verify_evidence.py is told
        # `env: 'python3\r': No such file or directory`.
        self._package()
        path = os.path.join(self.case.dir, "verify_evidence.py")
        with open(path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"\r\n", raw,
                         "verify_evidence.py must use LF endings")
        self.assertTrue(raw.startswith(b"#!"), "shebang missing")

    def test_verifier_is_executable_inside_the_archive(self):
        # unzip honours the Unix mode only when the archive says a Unix system
        # created the entry; built on Windows it defaults to FAT and the mode
        # is discarded.
        pkg = self._package()
        with zipfile.ZipFile(pkg["zip_path"]) as zf:
            entries = [i for i in zf.infolist()
                       if i.filename.endswith("verify_evidence.py")]
            self.assertEqual(len(entries), 1)
            info = entries[0]
            mode = (info.external_attr >> 16) & 0o7777
            self.assertTrue(mode & 0o111,
                            "verifier is not executable in the archive (mode %o)" % mode)
            self.assertEqual(info.create_system, 3,
                             "create_system must be Unix or unzip ignores the mode")

    def test_package_reports_a_root_hash_and_file_count(self):
        pkg = self._package()
        self.assertEqual(len(pkg["root_hash"]), 64)
        self.assertGreater(pkg["file_count"], 0)
        self.assertTrue(os.path.isfile(pkg["zip_path"]))

    def test_the_log_is_closed_by_sealing(self):
        # Anything written after the manifest is computed would not be covered
        # by it, and the package would fail its own verification.
        self._package()
        before = os.path.getsize(os.path.join(self.case.dir, "audit.jsonl"))
        self.case.log("post.seal", note="should not be recorded")
        after = os.path.getsize(os.path.join(self.case.dir, "audit.jsonl"))
        self.assertEqual(before, after,
                         "the audit log accepted a write after sealing")


if __name__ == "__main__":
    unittest.main()
