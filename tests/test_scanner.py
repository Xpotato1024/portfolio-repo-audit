from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from repo_audit.scanner import scan_repository


class ScanRepositoryTests(unittest.TestCase):
    def test_scan_collects_languages_large_files_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "ui.ts").write_text("const x: string = 'ok';\n", encoding="utf-8")
            (root / "config.txt").write_text(
                'api_key = "abcdefghijklmnop123456"\n', encoding="utf-8"
            )
            (root / "big.bin").write_bytes(b"a" * 3000)

            report = scan_repository(
                root,
                large_file_threshold_bytes=2000,
                max_text_scan_bytes=1024 * 1024,
                top_large_files=5,
            )

            self.assertEqual(report.total_files, 4)
            self.assertGreaterEqual(report.language_counts.get("Python", 0), 1)
            self.assertGreaterEqual(report.language_counts.get("TypeScript", 0), 1)
            self.assertEqual(len(report.large_files), 1)
            self.assertEqual(str(report.large_files[0].file), "big.bin")
            self.assertEqual(len(report.secret_findings), 1)
            self.assertEqual(report.secret_findings[0].rule, "Generic API Key Assignment")

    def test_scan_respects_excluded_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.js").write_text(
                "const token='aaaaaaaaaaaaaaaa';", encoding="utf-8"
            )
            (root / "main.py").write_text("print(1)\n", encoding="utf-8")

            report = scan_repository(root)

            self.assertEqual(report.total_files, 1)
            self.assertEqual(len(report.secret_findings), 0)


if __name__ == "__main__":
    unittest.main()
