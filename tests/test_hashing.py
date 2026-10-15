import hashlib
import tempfile
import unittest
from pathlib import Path

from core.database import Database
from core.hashing import ALGORITHMS, compare_hashes, hash_file


class HashingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary_directory.name) / "evidence.bin"
        self.path.write_bytes(b"DFTK test evidence")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_hash_file_streams_and_returns_all_supported_digests(self):
        expected = {
            algorithm: hashlib.new(algorithm, b"DFTK test evidence").hexdigest()
            for algorithm in ALGORITHMS
        }
        self.assertEqual(hash_file(self.path, chunk_size=3), expected)

    def test_matching_digests_verify_and_changed_or_missing_digest_fails(self):
        recorded = hash_file(self.path)
        status, details = compare_hashes(recorded, recorded)
        self.assertEqual(status, "Verified")
        self.assertEqual(set(details.values()), {"Match"})

        changed = dict(recorded)
        changed["sha256"] = "different"
        status, details = compare_hashes(recorded, changed)
        self.assertEqual(status, "Mismatch")
        self.assertEqual(details["sha256"], "Mismatch")
        self.assertEqual(details["md5"], "Match")

        incomplete = dict(recorded)
        incomplete["sha1"] = ""
        status, details = compare_hashes(incomplete, recorded)
        self.assertEqual(status, "Mismatch")
        self.assertEqual(details["sha1"], "Mismatch")

    def test_database_evidence_rows_can_be_compared_and_checks_are_recorded(self):
        database = Database(Path(self.temporary_directory.name) / "hashes.db")
        case_id = database.create_case("Hash test")
        hashes = hash_file(self.path)
        evidence_id = database.add_evidence(
            case_id,
            self.path.name,
            str(self.path),
            "File",
            self.path.stat().st_size,
            hashes,
        )
        evidence = database.list_all_evidence()[0]
        status, results = compare_hashes(evidence, hashes)
        self.assertEqual(status, "Verified")
        database.record_integrity_check(
            evidence_id, status, ",".join(results.values())
        )
        check = database.list_integrity_checks()[0]
        self.assertEqual(check["status"], "Verified")
        self.assertEqual(check["evidence_name"], self.path.name)


if __name__ == "__main__":
    unittest.main()
