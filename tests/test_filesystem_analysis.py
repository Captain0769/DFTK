import tempfile
import unittest
from pathlib import Path
from threading import Event

from core.filesystem_analysis import scan_directory


class FileSystemAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_scans_files_directories_and_hidden_files_without_following_links(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "report.txt").write_text("report", encoding="utf-8")
        (self.root / ".hidden").write_text("hidden", encoding="utf-8")
        records, errors = scan_directory(self.root)

        self.assertEqual(errors, [])
        by_name = {record["name"]: record for record in records}
        self.assertEqual(by_name["nested"]["type"], "Directory")
        self.assertEqual(by_name["report.txt"]["size"], 6)
        self.assertEqual(by_name["report.txt"]["extension"], ".txt")
        self.assertEqual(by_name["report.txt"]["mime_type"], "text/plain")
        self.assertTrue(by_name[".hidden"]["hidden"])
        self.assertEqual(
            [record["path"] for record in records],
            sorted([record["path"] for record in records], key=str.casefold),
        )

        target = self.root / "nested"
        link = self.root / "nested-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symbolic links are unavailable on this system")
        linked_records, _ = scan_directory(self.root)
        link_record = next(record for record in linked_records if record["name"] == "nested-link")
        self.assertEqual(link_record["type"], "Symbolic link")
        self.assertFalse(
            any(link in Path(record["path"]).parents for record in linked_records)
        )

    def test_rejects_non_directory_and_honors_cancellation(self):
        file_path = self.root / "file.txt"
        file_path.write_text("data", encoding="utf-8")
        with self.assertRaises(NotADirectoryError):
            scan_directory(file_path)

        cancel = Event()
        cancel.set()
        records, _errors = scan_directory(self.root, cancel)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
