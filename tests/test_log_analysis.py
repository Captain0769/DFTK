import json
import tempfile
import unittest
from pathlib import Path

from core.database import Database
from core.log_analysis import parse_log


class LogAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_parses_text_lines_and_normalizes_severity_and_timestamp(self):
        source = self.root / "system.log"
        source.write_text(
            "2025-02-03 10:11:12 FATAL disk failure\n\n"
            "2025/02/03 WARNING retry scheduled\n",
            encoding="utf-8",
        )

        events = parse_log(source)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["line"], "1")
        self.assertEqual(events[0]["timestamp"], "2025-02-03 10:11:12")
        self.assertEqual(events[0]["severity"], "CRITICAL")
        self.assertEqual(events[1]["severity"], "WARNING")

    def test_parses_csv_and_json_records(self):
        csv_path = self.root / "events.csv"
        csv_path.write_text(
            "timestamp,level,message\n2025-01-02 03:04:05,ERR,Disk error\n",
            encoding="utf-8",
        )
        csv_events = parse_log(csv_path)
        self.assertEqual(csv_events[0]["severity"], "ERROR")
        self.assertEqual(csv_events[0]["timestamp"], "2025-01-02 03:04:05")

        json_path = self.root / "events.json"
        json_path.write_text(
            json.dumps({"events": [{"time": "2025-01-02", "severity": "WARN", "message": "Retry"}]}),
            encoding="utf-8",
        )
        json_events = parse_log(json_path)
        self.assertEqual(json_events[0]["severity"], "WARNING")
        self.assertIn("message: Retry", json_events[0]["message"])

    def test_parses_json_lines_and_scalar_json_roots(self):
        jsonl_path = self.root / "events.jsonl"
        jsonl_path.write_text(
            '{"level":"INFO","message":"Started"}\n"standalone warning"\n',
            encoding="utf-8",
        )
        jsonl_events = parse_log(jsonl_path)
        self.assertEqual([event["severity"] for event in jsonl_events], ["INFO", "WARNING"])

        scalar_path = self.root / "event.json"
        scalar_path.write_text('"single event"', encoding="utf-8")
        self.assertEqual(parse_log(scalar_path)[0]["message"], "single event")

    def test_rejects_unsupported_extension_and_malformed_json_lines(self):
        unsupported = self.root / "events.evtx"
        unsupported.write_text("event", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unsupported log format"):
            parse_log(unsupported)

        malformed = self.root / "broken.jsonl"
        malformed.write_text('{"message":\n', encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            parse_log(malformed)

    def test_log_analyses_are_persisted_and_linked_to_evidence_when_available(self):
        database = Database(self.root / "logs.db")
        case_id = database.create_case("Log case")
        source = self.root / "registered.log"
        source.write_text("ERROR: Failed login", encoding="utf-8")
        evidence_id = database.add_evidence(
            case_id, source.name, str(source), "Log", source.stat().st_size, {}
        )
        events = parse_log(source)

        database.record_log_analysis(
            str(source), json.dumps(events), len(events), evidence_id=evidence_id
        )

        records = database.list_log_analyses()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["evidence_id"], evidence_id)
        self.assertEqual(records[0]["source_path"], str(source))
        self.assertEqual(json.loads(records[0]["events_json"]), events)
        self.assertTrue(any(row["action"] == "Log analyzed" for row in database.list_activity()))


if __name__ == "__main__":
    unittest.main()
