import tempfile
import unittest
from pathlib import Path

from core.database import Database


class EvidenceManagementDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "evidence.db"
        self.database = Database(database_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_case_details_evidence_and_custody_are_persisted(self):
        case_id = self.database.create_case(
            "Case 01", "Initial description", "Investigator"
        )
        self.database.update_case_details(
            case_id, "Case 01 revised", "Updated description", "Lead investigator"
        )
        case = self.database.list_cases()[0]
        self.assertEqual(case["name"], "Case 01 revised")
        self.assertEqual(case["description"], "Updated description")
        self.assertEqual(case["investigator"], "Lead investigator")

        evidence_path = Path(self.temporary_directory.name) / "item.bin"
        evidence_path.write_bytes(b"evidence")
        evidence_id = self.database.add_evidence(
            case_id,
            evidence_path.name,
            str(evidence_path),
            "File",
            evidence_path.stat().st_size,
            {
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
            },
        )
        self.assertTrue(self.database.has_evidence_path(case_id, evidence_path))
        self.assertFalse(
            self.database.has_evidence_path(
                case_id, Path(self.temporary_directory.name) / "different.bin"
            )
        )

        original_custody = self.database.list_custody(evidence_id)
        self.assertEqual(len(original_custody), 1)
        self.assertEqual(original_custody[0]["action"], "Evidence added")
        self.database.add_custody(evidence_id, "Transferred", "Investigator", "Sealed bag")
        custody = self.database.list_custody(evidence_id)
        self.assertEqual(len(custody), 2)
        self.assertEqual(custody[0]["action"], "Transferred")
        self.assertEqual(custody[0]["notes"], "Sealed bag")

    def test_evidence_is_case_scoped(self):
        first_case = self.database.create_case("First")
        second_case = self.database.create_case("Second")
        evidence_path = Path(self.temporary_directory.name) / "same.bin"
        evidence_path.write_bytes(b"data")
        hashes = {"md5": "", "sha1": "", "sha256": "", "sha512": ""}
        self.database.add_evidence(
            first_case, "same.bin", str(evidence_path), "File", 4, hashes
        )
        self.assertTrue(self.database.has_evidence_path(first_case, evidence_path))
        self.assertFalse(self.database.has_evidence_path(second_case, evidence_path))


if __name__ == "__main__":
    unittest.main()
