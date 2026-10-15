import csv
import json
import re
from pathlib import Path


SEVERITIES = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN")
SEVERITY_PATTERN = re.compile(
    r"\b(CRITICAL|FATAL|ERROR|ERR|WARNING|WARN|INFO|DEBUG)\b", re.IGNORECASE
)
TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}[-/]\d{2}[-/]\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\b"
)


def parse_log(path):
    """Parse common offline log formats into normalized event dictionaries."""
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return _parse_json(file_path)
    if suffix in {".jsonl", ".ndjson"}:
        return _parse_json_lines(file_path)
    if suffix == ".csv":
        return _parse_csv(file_path)
    if suffix in {".txt", ".log"}:
        return _parse_text(file_path)
    raise ValueError("Unsupported log format. Choose TXT, LOG, CSV, JSON, or JSONL.")


def _parse_text(path):
    events = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, 1):
            text = line.strip()
            if text:
                events.append(_event(line_number, text, text))
    return events


def _parse_csv(path):
    events = []
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as log_file:
        for line_number, row in enumerate(csv.DictReader(log_file), 2):
            values = {str(key).lower(): str(value or "") for key, value in row.items()}
            text = " | ".join(value for value in values.values() if value)
            timestamp = values.get("timestamp") or values.get("time") or values.get("date")
            severity = values.get("severity") or values.get("level") or text
            events.append(_event(line_number, text, severity, timestamp))
    return events


def _parse_json(path):
    with path.open("r", encoding="utf-8-sig", errors="replace") as log_file:
        payload = json.load(log_file)
    records = _json_records(payload)
    events = []
    for line_number, record in enumerate(records, 1):
        if isinstance(record, dict):
            values = {str(key).lower(): str(value or "") for key, value in record.items()}
            text = " | ".join("{}: {}".format(key, value) for key, value in values.items())
            timestamp = values.get("timestamp") or values.get("time") or values.get("date")
            severity = values.get("severity") or values.get("level") or text
        else:
            text = str(record)
            timestamp = ""
            severity = text
        events.append(_event(line_number, text, severity, timestamp))
    return events


def _parse_json_lines(path):
    events = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if isinstance(record, dict):
                values = {str(key).lower(): str(value or "") for key, value in record.items()}
                text = " | ".join("{}: {}".format(key, value) for key, value in values.items())
                timestamp = values.get("timestamp") or values.get("time") or values.get("date")
                severity = values.get("severity") or values.get("level") or text
            else:
                text = str(record)
                timestamp = ""
                severity = text
            events.append(_event(line_number, text, severity, timestamp))
    return events


def _json_records(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        records = payload.get("events", payload.get("logs"))
        if records is None:
            return [payload]
        return records if isinstance(records, list) else [records]
    return [payload]


def _event(line_number, text, severity_text, timestamp=""):
    match = SEVERITY_PATTERN.search(severity_text)
    severity = match.group(1).upper() if match else "UNKNOWN"
    if severity == "FATAL":
        severity = "CRITICAL"
    if severity in {"ERR", "WARN"}:
        severity = "ERROR" if severity == "ERR" else "WARNING"
    return {
        "line": str(line_number),
        "timestamp": timestamp or _find_timestamp(text),
        "severity": severity if severity in SEVERITIES else "UNKNOWN",
        "message": text,
    }


def _find_timestamp(text):
    match = TIMESTAMP_PATTERN.search(text)
    return match.group(0) if match else ""
