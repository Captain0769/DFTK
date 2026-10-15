import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from core.database import Database
from core.timeline import filter_events, sort_events


class TimelineAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database = Database(self.root / "timeline.db")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_timeline_combines_case_evidence_integrity_metadata_custody_reports_and_logs(self):
        case_id = self.database.create_case("Timeline case", investigator="Analyst")
        source = self.root / "evidence.log"
        source.write_text("ERROR: login failed", encoding="utf-8")
        evidence_id = self.database.add_evidence(
            case_id, source.name, str(source), "Log", source.stat().st_size, {}
        )
        self.database.add_custody(evidence_id, "Transferred", "Investigator", "Sealed bag")
        self.database.record_integrity_check(evidence_id, "Verified", "sha256")
        self.database.record_metadata_findings(
            evidence_id, json.dumps({"Name": source.name, "Size (bytes)": "18"})
        )
        events = [
            {
                "line": "1",
                "timestamp": "2025-03-04T10:00:00+00:00",
                "severity": "ERROR",
                "message": "login failed",
            },
            {
                "line": "2",
                "timestamp": "",
                "severity": "INFO",
                "message": "timestamp missing",
            },
        ]
        self.database.record_log_analysis(
            str(source), json.dumps(events), len(events), evidence_id
        )
        self.database.record_report(case_id, str(self.root / "report.pdf"), "PDF")

        timeline = self.database.list_timeline()
        event_types = {event["event_type"] for event in timeline}

        self.assertTrue(
            {
                "Case created",
                "Evidence added",
                "Chain of custody",
                "Integrity check",
                "Metadata analysis",
                "Log analysis",
                "Log event",
                "Report generated",
            }.issubset(event_types)
        )
        self.assertEqual(
            sum(event["event_type"] == "Log event" for event in timeline), 2
        )
        self.assertTrue(all(event["case_id"] == case_id for event in timeline))
        self.assertTrue(all(event["case_name"] == "Timeline case" for event in timeline))
        self.assertEqual(len(self.database.list_timeline(case_id)), len(timeline))
        self.assertEqual(self.database.list_timeline(-1), [])

    def test_timeline_filters_by_text_type_case_and_inclusive_dates(self):
        events = [
            {
                "timestamp": "2025-03-04T10:00:00+00:00",
                "event_type": "Log event",
                "subject": "system.log",
                "details": "ERROR login failed",
                "case_id": 1,
                "case_name": "Case A",
            },
            {
                "timestamp": "2025-03-05T10:00:00+00:00",
                "event_type": "Evidence added",
                "subject": "image.png",
                "details": "Image",
                "case_id": 2,
                "case_name": "Case B",
            },
            {
                "timestamp": "",
                "event_type": "Log event",
                "subject": "system.log",
                "details": "untimed",
                "case_id": 1,
                "case_name": "Case A",
            },
        ]

        filtered = filter_events(
            events,
            query="LOGIN",
            event_type="Log event",
            case_id=1,
            start_date=date(2025, 3, 4),
            end_date=date(2025, 3, 4),
        )

        self.assertEqual(filtered, [events[0]])
        self.assertEqual(
            filter_events(events, start_date=date(2025, 3, 4)), [events[0], events[1]]
        )

    def test_sort_handles_mixed_timezone_and_invalid_timestamps(self):
        events = [
            {"timestamp": "invalid", "subject": "undated"},
            {"timestamp": "2025-03-04T10:00:00", "subject": "naive"},
            {"timestamp": "2025-03-04T11:00:00+02:00", "subject": "offset"},
            {"timestamp": "2025-03-04T10:30:00Z", "subject": "newest"},
        ]

        sorted_events = sort_events(events)

        self.assertEqual(
            [event["subject"] for event in sorted_events],
            ["newest", "naive", "offset", "undated"],
        )


if __name__ == "__main__":
    unittest.main()
