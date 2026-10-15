import json
import tempfile
import unittest
from pathlib import Path

from core.database import Database


class GlobalSearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database = Database(self.root / "search.db")
        self.case_a = self.database.create_case(
            "Harbor Incident", "Recovered laptop", "Analyst North"
        )
        self.case_b = self.database.create_case("Other Case")
        source = self.root / "incident.log"
        source.write_text("ERROR access denied", encoding="utf-8")
        self.evidence_id = self.database.add_evidence(
            self.case_a,
            source.name,
            str(source),
            "Log",
            source.stat().st_size,
            {
                "md5": "abc123",
                "sha1": "legacy456",
                "sha256": "primary789",
                "sha512": "strong000",
            },
        )
        self.database.add_custody(
            self.evidence_id, "Transferred", "Analyst North", "vault-blue"
        )
        self.database.record_integrity_check(self.evidence_id, "Verified", "sha256")
        self.database.record_metadata_findings(
            self.evidence_id,
            json.dumps({"DeviceLabel": "LAPTOP-42", "Owner": "North"}),
        )
        self.log_events = [
            {
                "line": "1",
                "timestamp": "2025-04-03T10:00:00+00:00",
                "severity": "ERROR",
                "message": "credential spray detected",
            }
        ]
        self.database.record_log_analysis(
            str(source),
            json.dumps(self.log_events),
            len(self.log_events),
            evidence_id=self.evidence_id,
        )
        self.database.record_report(self.case_a, str(self.root / "incident-report.pdf"), "PDF")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_search_covers_investigation_sources(self):
        expected_categories = {
            "Harbor": "Case",
            "primary789": "Evidence",
            "vault-blue": "Chain of custody",
            "sha256": "Integrity check",
            "LAPTOP-42": "Metadata analysis",
            "credential spray": "Log event",
            "incident-report.pdf": "Report",
        }
        for query, expected_type in expected_categories.items():
            with self.subTest(query=query):
                results = self.database.search(query)
                self.assertTrue(
                    any(result["result_type"] == expected_type for result in results),
                    results,
                )

    def test_search_filters_by_result_type_and_case(self):
        evidence_results = self.database.search(
            "incident", result_type="Evidence", case_id=self.case_a
        )
        self.assertEqual(len(evidence_results), 1)
        self.assertEqual(evidence_results[0]["evidence_id"], self.evidence_id)

        other_case_results = self.database.search("incident", case_id=self.case_b)
        self.assertEqual(other_case_results, [])
        log_event_results = self.database.search(
            "credential spray", result_type="Log event"
        )
        self.assertEqual(len(log_event_results), 1)
        self.assertEqual(log_event_results[0]["timestamp"], self.log_events[0]["timestamp"])
        log_analysis_results = self.database.search(
            "incident.log", result_type="Log analysis"
        )
        self.assertEqual(len(log_analysis_results), 1)
        self.assertEqual(log_analysis_results[0]["evidence_id"], self.evidence_id)

    def test_search_treats_wildcards_as_literal_text_and_rejects_empty_query(self):
        source = self.root / "literal%_name.txt"
        source.write_text("literal", encoding="utf-8")
        self.database.add_evidence(
            self.case_b, source.name, str(source), "File", source.stat().st_size, {}
        )

        matches = self.database.search("%_name")

        self.assertTrue(any(result["title"] == source.name for result in matches))
        self.assertEqual(self.database.search(""), [])
        self.assertEqual(self.database.search("   "), [])

    def test_star_returns_all_results_and_respects_type_case_and_limit_filters(self):
        all_results = self.database.search("*")
        result_types = {result["result_type"] for result in all_results}
        self.assertTrue(
            {
                "Case",
                "Evidence",
                "Chain of custody",
                "Integrity check",
                "Metadata analysis",
                "Log analysis",
                "Log event",
                "Report",
                "Activity",
            }.issubset(result_types)
        )

        evidence_results = self.database.search("*", result_type="Evidence")
        self.assertEqual(len(evidence_results), 1)
        self.assertEqual(evidence_results[0]["evidence_id"], self.evidence_id)

        case_results = self.database.search("*", case_id=self.case_a)
        self.assertTrue(case_results)
        self.assertTrue(all(result["case_id"] == self.case_a for result in case_results))
        self.assertEqual(
            self.database.search("*", result_type="Evidence", case_id=self.case_b), []
        )
        self.assertEqual(len(self.database.search("*", limit=3)), 3)

    def test_search_respects_result_limit(self):
        for index in range(8):
            self.database.add_custody(
                self.evidence_id, "Reviewed", "Analyst", "repeatable-match-{}".format(index)
            )

        results = self.database.search("repeatable-match", limit=3)

        self.assertEqual(len(results), 3)


if __name__ == "__main__":
    unittest.main()
