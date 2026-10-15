import tempfile
import unittest
from pathlib import Path

from core.database import Database


class DashboardDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "dashboard.db"
        self.database = Database(database_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_dashboard_summary_uses_recorded_data(self):
        self.assertEqual(
            self.database.dashboard_summary(),
            {
                "open_cases": 0,
                "total_cases": 0,
                "evidence": 0,
                "integrity_checks": 0,
                "reports": 0,
            },
        )

        case_id = self.database.create_case("Investigation A", investigator="Analyst")
        evidence_id = self.database.add_evidence(
            case_id,
            "sample.txt",
            "C:/evidence/sample.txt",
            "File",
            12,
            {
                "md5": "md5-value",
                "sha1": "sha1-value",
                "sha256": "sha256-value",
                "sha512": "sha512-value",
            },
        )
        self.database.record_integrity_check(evidence_id, "Verified", "md5,sha1,sha256,sha512")
        self.database.record_report(case_id, "report.pdf", "PDF")

        summary = self.database.dashboard_summary()
        self.assertEqual(summary["open_cases"], 1)
        self.assertEqual(summary["total_cases"], 1)
        self.assertEqual(summary["evidence"], 1)
        self.assertEqual(summary["integrity_checks"], 1)
        self.assertEqual(summary["reports"], 1)
        self.assertEqual(self.database.list_recent_cases()[0]["evidence_count"], 1)

        self.database.update_case_status(case_id, "Closed")
        self.assertEqual(self.database.dashboard_summary()["open_cases"], 0)


if __name__ == "__main__":
    unittest.main()
