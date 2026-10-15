from contextlib import contextmanager
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "dftk.db"


class Database:
    """Small SQLite repository for offline investigations."""

    def __init__(self, path=DATABASE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._create_schema()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _create_schema(self):
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    investigator TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'Open',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    size INTEGER NOT NULL DEFAULT 0,
                    md5 TEXT NOT NULL DEFAULT '',
                    sha1 TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL DEFAULT '',
                    sha512 TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS integrity_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    algorithms TEXT NOT NULL,
                    checked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    format TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                    metadata_json TEXT NOT NULL,
                    extracted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS log_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
                    source_path TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def create_case(self, name, description="", investigator=""):
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO cases (name, description, investigator, created_at) VALUES (?, ?, ?, ?)",
                (name, description, investigator, self._now()),
            )
            self.log_activity(connection, "Case created", name)
            return cursor.lastrowid

    def list_cases(self):
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM cases ORDER BY created_at DESC, id DESC"
            ).fetchall()

    def update_case_details(self, case_id, name, description, investigator):
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE cases
                SET name = ?, description = ?, investigator = ?
                WHERE id = ?
                """,
                (name, description, investigator, case_id),
            )
            self.log_activity(connection, "Case details updated", name)

    def add_evidence(self, case_id, name, path, evidence_type, size, hashes):
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO evidence
                (case_id, name, path, evidence_type, size, md5, sha1, sha256, sha512, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    name,
                    path,
                    evidence_type,
                    size,
                    hashes.get("md5", ""),
                    hashes.get("sha1", ""),
                    hashes.get("sha256", ""),
                    hashes.get("sha512", ""),
                    self._now(),
                ),
            )
            evidence_id = cursor.lastrowid
            connection.execute(
                """
                INSERT INTO custody (evidence_id, action, actor, notes, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (evidence_id, "Evidence added", "DFTK user", "Initial acquisition", self._now()),
            )
            self.log_activity(connection, "Evidence added", name)
            return evidence_id

    def list_evidence(self, case_id):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT * FROM evidence
                WHERE case_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (case_id,),
            ).fetchall()

    def has_evidence_path(self, case_id, path):
        normalized_path = str(Path(path).resolve()).casefold()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT path FROM evidence WHERE case_id = ?", (case_id,)
            ).fetchall()
        return any(str(Path(row["path"]).resolve()).casefold() == normalized_path for row in rows)

    def list_all_evidence(self):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT evidence.*, cases.name AS case_name
                FROM evidence
                JOIN cases ON cases.id = evidence.case_id
                ORDER BY evidence.created_at DESC
                """
            ).fetchall()

    def list_custody(self, evidence_id):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT * FROM custody
                WHERE evidence_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (evidence_id,),
            ).fetchall()

    def add_custody(self, evidence_id, action, actor, notes=""):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO custody (evidence_id, action, actor, notes, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (evidence_id, action, actor, notes, self._now()),
            )
            self.log_activity(connection, action, notes or str(evidence_id))

    def list_activity(self, limit=8):
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM activity ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def list_all_activity(self, limit=500):
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM activity ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()

    def list_timeline(self, case_id=None):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT cases.created_at AS timestamp, 'Case created' AS event_type,
                       cases.name AS subject, cases.investigator AS details,
                       cases.id AS case_id, cases.name AS case_name
                FROM cases
                UNION ALL
                SELECT evidence.created_at, 'Evidence added',
                       evidence.name, evidence.evidence_type || ' | ' || evidence.path,
                       cases.id, cases.name
                FROM evidence
                JOIN cases ON cases.id = evidence.case_id
                UNION ALL
                SELECT custody.created_at, 'Chain of custody',
                       evidence.name,
                       custody.action || ' | ' || custody.actor || ' | ' || custody.notes,
                       cases.id, cases.name
                FROM custody
                JOIN evidence ON evidence.id = custody.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                UNION ALL
                SELECT integrity_checks.checked_at, 'Integrity check',
                       evidence.name,
                       integrity_checks.status || ' | Algorithms: ' || integrity_checks.algorithms,
                       cases.id, cases.name
                FROM integrity_checks
                JOIN evidence ON evidence.id = integrity_checks.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                UNION ALL
                SELECT reports.generated_at, 'Report generated',
                       reports.format, reports.path,
                       cases.id, cases.name
                FROM reports
                JOIN cases ON cases.id = reports.case_id
                UNION ALL
                SELECT activity.created_at, 'Activity', activity.action, activity.details,
                       NULL, ''
                FROM activity
                WHERE activity.action NOT IN (
                    'Case created', 'Evidence added', 'Metadata analyzed', 'Log analyzed',
                    'Report generated', 'Integrity check verified',
                    'Integrity check mismatch'
                )
                AND activity.action NOT IN (SELECT action FROM custody)
                """
            ).fetchall()
            events = [dict(row) for row in rows]

            metadata_rows = connection.execute(
                """
                SELECT metadata_findings.extracted_at AS timestamp,
                       evidence.name AS subject, metadata_findings.metadata_json,
                       cases.id AS case_id, cases.name AS case_name
                FROM metadata_findings
                JOIN evidence ON evidence.id = metadata_findings.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                """
            ).fetchall()
            for row in metadata_rows:
                try:
                    metadata = json.loads(row["metadata_json"])
                except json.JSONDecodeError:
                    details = "Saved metadata data is invalid"
                else:
                    details = "{} metadata properties captured".format(
                        len(metadata) if isinstance(metadata, dict) else 0
                    )
                events.append(
                    {
                        "timestamp": row["timestamp"],
                        "event_type": "Metadata analysis",
                        "subject": row["subject"],
                        "details": details,
                        "case_id": row["case_id"],
                        "case_name": row["case_name"],
                    }
                )

            log_rows = connection.execute(
                """
                SELECT log_analyses.analyzed_at, log_analyses.source_path,
                       log_analyses.events_json, evidence.name AS evidence_name,
                       cases.id AS case_id, cases.name AS case_name
                FROM log_analyses
                LEFT JOIN evidence ON evidence.id = log_analyses.evidence_id
                LEFT JOIN cases ON cases.id = evidence.case_id
                """
            ).fetchall()
            for row in log_rows:
                subject = row["evidence_name"] or Path(row["source_path"]).name
                try:
                    log_events = json.loads(row["events_json"])
                    if not isinstance(log_events, list):
                        raise ValueError("Saved log events are not a list")
                except (json.JSONDecodeError, ValueError):
                    log_events = None
                    details = "Saved parsed-event data is invalid"
                else:
                    details = "{} source event(s) parsed".format(len(log_events))
                events.append(
                    {
                        "timestamp": row["analyzed_at"],
                        "event_type": "Log analysis",
                        "subject": subject,
                        "details": details,
                        "case_id": row["case_id"],
                        "case_name": row["case_name"] or "",
                    }
                )
                if log_events is None:
                    continue
                for log_event in log_events:
                    if not isinstance(log_event, dict):
                        continue
                    timestamp = str(log_event.get("timestamp") or "")
                    event_details = "Line {} | {} | {}".format(
                        log_event.get("line", ""),
                        log_event.get("severity", "UNKNOWN"),
                        log_event.get("message", ""),
                    )
                    events.append(
                        {
                            "timestamp": timestamp,
                            "event_type": "Log event",
                            "subject": subject,
                            "details": event_details,
                            "case_id": row["case_id"],
                            "case_name": row["case_name"] or "",
                        }
                    )

        if case_id is not None:
            events = [event for event in events if event["case_id"] == case_id]
        return events

    def search(self, query, result_type=None, case_id=None, limit=500):
        search_term = str(query).strip()
        if not search_term:
            return []
        show_all = search_term == "*"
        escaped_term = (
            search_term.casefold()
            .replace("!", "!!")
            .replace("%", "!%")
            .replace("_", "!_")
        )
        pattern = "%" + escaped_term + "%"
        predicates = {
            "Case": (
                "lower(cases.name) LIKE ? ESCAPE '!' OR "
                "lower(cases.description) LIKE ? ESCAPE '!' OR "
                "lower(cases.investigator) LIKE ? ESCAPE '!' OR "
                "lower(cases.status) LIKE ? ESCAPE '!'"
            ),
            "Evidence": (
                "lower(evidence.name) LIKE ? ESCAPE '!' OR "
                "lower(evidence.path) LIKE ? ESCAPE '!' OR "
                "lower(evidence.evidence_type) LIKE ? ESCAPE '!' OR "
                "lower(evidence.md5) LIKE ? ESCAPE '!' OR "
                "lower(evidence.sha1) LIKE ? ESCAPE '!' OR "
                "lower(evidence.sha256) LIKE ? ESCAPE '!' OR "
                "lower(evidence.sha512) LIKE ? ESCAPE '!'"
            ),
            "Chain of custody": (
                "lower(evidence.name) LIKE ? ESCAPE '!' OR "
                "lower(custody.action) LIKE ? ESCAPE '!' OR "
                "lower(custody.actor) LIKE ? ESCAPE '!' OR "
                "lower(custody.notes) LIKE ? ESCAPE '!'"
            ),
            "Activity": (
                "lower(activity.action) LIKE ? ESCAPE '!' OR "
                "lower(activity.details) LIKE ? ESCAPE '!'"
            ),
            "Integrity check": (
                "lower(evidence.name) LIKE ? ESCAPE '!' OR "
                "lower(integrity_checks.status) LIKE ? ESCAPE '!' OR "
                "lower(integrity_checks.algorithms) LIKE ? ESCAPE '!'"
            ),
            "Report": (
                "lower(cases.name) LIKE ? ESCAPE '!' OR "
                "lower(reports.path) LIKE ? ESCAPE '!' OR "
                "lower(reports.format) LIKE ? ESCAPE '!'"
            ),
            "Metadata analysis": (
                "lower(evidence.name) LIKE ? ESCAPE '!' OR "
                "lower(metadata_findings.metadata_json) LIKE ? ESCAPE '!'"
            ),
            "Log analysis": (
                "lower(log_analyses.source_path) LIKE ? ESCAPE '!' OR "
                "lower(coalesce(evidence.name, '')) LIKE ? ESCAPE '!'"
            ),
        }
        if show_all:
            predicates = {category: "1 = 1" for category in predicates}
        queries = {
            "Case": """
                SELECT 'Case' AS result_type, cases.name AS title,
                       cases.description || ' | Investigator: ' || cases.investigator ||
                       ' | Status: ' || cases.status AS details,
                       cases.created_at AS timestamp, cases.id AS case_id,
                       cases.name AS case_name, NULL AS evidence_id
                FROM cases WHERE {predicate}
                ORDER BY cases.created_at DESC LIMIT ?
            """,
            "Evidence": """
                SELECT 'Evidence' AS result_type, evidence.name AS title,
                       evidence.evidence_type || ' | ' || evidence.path ||
                       ' | MD5: ' || evidence.md5 || ' | SHA-1: ' || evidence.sha1 ||
                       ' | SHA-256: ' || evidence.sha256 || ' | SHA-512: ' || evidence.sha512
                       AS details,
                       evidence.created_at AS timestamp, cases.id AS case_id,
                       cases.name AS case_name, evidence.id AS evidence_id
                FROM evidence JOIN cases ON cases.id = evidence.case_id
                WHERE {predicate}
                ORDER BY evidence.created_at DESC LIMIT ?
            """,
            "Chain of custody": """
                SELECT 'Chain of custody' AS result_type, evidence.name AS title,
                       custody.action || ' | ' || custody.actor || ' | ' || custody.notes
                       AS details, custody.created_at AS timestamp,
                       cases.id AS case_id, cases.name AS case_name,
                       evidence.id AS evidence_id
                FROM custody JOIN evidence ON evidence.id = custody.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                WHERE {predicate}
                ORDER BY custody.created_at DESC LIMIT ?
            """,
            "Activity": """
                SELECT 'Activity' AS result_type, activity.action AS title,
                       activity.details AS details, activity.created_at AS timestamp,
                       NULL AS case_id, '' AS case_name, NULL AS evidence_id
                FROM activity WHERE {predicate}
                ORDER BY activity.created_at DESC LIMIT ?
            """,
            "Integrity check": """
                SELECT 'Integrity check' AS result_type, evidence.name AS title,
                       integrity_checks.status || ' | Algorithms: ' ||
                       integrity_checks.algorithms AS details,
                       integrity_checks.checked_at AS timestamp, cases.id AS case_id,
                       cases.name AS case_name, evidence.id AS evidence_id
                FROM integrity_checks JOIN evidence ON evidence.id = integrity_checks.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                WHERE {predicate}
                ORDER BY integrity_checks.checked_at DESC LIMIT ?
            """,
            "Report": """
                SELECT 'Report' AS result_type, reports.format AS title,
                       reports.path AS details, reports.generated_at AS timestamp,
                       cases.id AS case_id, cases.name AS case_name, NULL AS evidence_id
                FROM reports JOIN cases ON cases.id = reports.case_id
                WHERE {predicate}
                ORDER BY reports.generated_at DESC LIMIT ?
            """,
            "Metadata analysis": """
                SELECT 'Metadata analysis' AS result_type, evidence.name AS title,
                       metadata_findings.metadata_json AS details,
                       metadata_findings.extracted_at AS timestamp,
                       cases.id AS case_id, cases.name AS case_name,
                       evidence.id AS evidence_id
                FROM metadata_findings JOIN evidence
                  ON evidence.id = metadata_findings.evidence_id
                JOIN cases ON cases.id = evidence.case_id
                WHERE {predicate}
                ORDER BY metadata_findings.extracted_at DESC LIMIT ?
            """,
            "Log analysis": """
                SELECT 'Log analysis' AS result_type,
                       coalesce(evidence.name, log_analyses.source_path) AS title,
                       log_analyses.source_path AS details,
                       log_analyses.analyzed_at AS timestamp,
                       cases.id AS case_id, coalesce(cases.name, '') AS case_name,
                       evidence.id AS evidence_id
                FROM log_analyses LEFT JOIN evidence
                  ON evidence.id = log_analyses.evidence_id
                LEFT JOIN cases ON cases.id = evidence.case_id
                WHERE {predicate}
                ORDER BY log_analyses.analyzed_at DESC LIMIT ?
            """,
        }
        if result_type in (None, "All result types"):
            selected_types = list(queries)
        elif result_type in queries:
            selected_types = [result_type]
        elif result_type == "Log event":
            selected_types = []
        else:
            return []
        results = []
        with self._connect() as connection:
            for category in selected_types:
                predicate = predicates[category]
                parameter_count = predicate.count("?")
                rows = connection.execute(
                    queries[category].format(predicate=predicate),
                    (pattern,) * parameter_count + (limit,),
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    if case_id is not None and item["case_id"] != case_id:
                        continue
                    item["details"] = str(item["details"] or "")
                    if category == "Metadata analysis":
                        try:
                            metadata = json.loads(item["details"])
                        except json.JSONDecodeError:
                            item["details"] = "Saved metadata data is invalid"
                        else:
                            if isinstance(metadata, dict):
                                item["details"] = "Metadata keys: " + ", ".join(
                                    str(key) for key in list(metadata)[:12]
                                )
                            else:
                                item["details"] = "Metadata analysis saved"
                    elif len(item["details"]) > 1000:
                        item["details"] = item["details"][:997] + "..."
                    results.append(item)

            if result_type in (None, "All result types", "Log event"):
                log_rows = connection.execute(
                    """
                    SELECT log_analyses.source_path, log_analyses.events_json,
                           log_analyses.analyzed_at, evidence.name AS evidence_name,
                           evidence.id AS evidence_id, cases.id AS case_id,
                           cases.name AS case_name
                    FROM log_analyses
                    LEFT JOIN evidence ON evidence.id = log_analyses.evidence_id
                    LEFT JOIN cases ON cases.id = evidence.case_id
                    ORDER BY log_analyses.analyzed_at DESC
                    """
                ).fetchall()
                for log_row in log_rows:
                    if case_id is not None and log_row["case_id"] != case_id:
                        continue
                    try:
                        log_events = json.loads(log_row["events_json"])
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(log_events, list):
                        continue
                    for event in log_events:
                        if not isinstance(event, dict):
                            continue
                        searchable = " ".join(
                            str(event.get(key) or "")
                            for key in ("timestamp", "line", "severity", "message")
                        )
                        if not show_all and search_term.casefold() not in searchable.casefold():
                            continue
                        results.append(
                            {
                                "result_type": "Log event",
                                "title": log_row["evidence_name"]
                                or Path(log_row["source_path"]).name,
                                "details": "Line {} | {} | {}".format(
                                    event.get("line", ""),
                                    event.get("severity", "UNKNOWN"),
                                    event.get("message", ""),
                                ),
                                "timestamp": str(event.get("timestamp") or ""),
                                "case_id": log_row["case_id"],
                                "case_name": log_row["case_name"] or "",
                                "evidence_id": log_row["evidence_id"],
                            }
                        )

        results.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        return results[:max(0, limit)]

    def update_case_status(self, case_id, status):
        with self._connect() as connection:
            connection.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
            self.log_activity(connection, "Case status changed", status)

    def dashboard_summary(self):
        with self._connect() as connection:
            return {
                "open_cases": connection.execute(
                    "SELECT COUNT(*) FROM cases WHERE lower(status) != 'closed'"
                ).fetchone()[0],
                "total_cases": connection.execute(
                    "SELECT COUNT(*) FROM cases"
                ).fetchone()[0],
                "evidence": connection.execute(
                    "SELECT COUNT(*) FROM evidence"
                ).fetchone()[0],
                "integrity_checks": connection.execute(
                    "SELECT COUNT(*) FROM integrity_checks"
                ).fetchone()[0],
                "reports": connection.execute(
                    "SELECT COUNT(*) FROM reports"
                ).fetchone()[0],
            }

    def list_recent_cases(self, limit=5):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT cases.*, COUNT(evidence.id) AS evidence_count
                FROM cases
                LEFT JOIN evidence ON evidence.case_id = cases.id
                GROUP BY cases.id
                ORDER BY cases.created_at DESC, cases.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    def record_integrity_check(self, evidence_id, status, algorithms):
        checked_at = self._now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO integrity_checks (evidence_id, status, algorithms, checked_at)
                VALUES (?, ?, ?, ?)
                """,
                (evidence_id, status, algorithms, checked_at),
            )
            self.log_activity(
                connection,
                "Integrity check {}".format(status.lower()),
                "Evidence ID {}".format(evidence_id),
            )

    def record_metadata_findings(self, evidence_id, metadata_json):
        extracted_at = self._now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metadata_findings (evidence_id, metadata_json, extracted_at)
                VALUES (?, ?, ?)
                """,
                (evidence_id, metadata_json, extracted_at),
            )
            evidence = connection.execute(
                "SELECT name FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            self.log_activity(
                connection,
                "Metadata analyzed",
                evidence["name"] if evidence is not None else str(evidence_id),
            )

    def list_metadata_findings(self, evidence_id, limit=20):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT * FROM metadata_findings
                WHERE evidence_id = ?
                ORDER BY extracted_at DESC, id DESC
                LIMIT ?
                """,
                (evidence_id, limit),
            ).fetchall()

    def record_log_analysis(self, source_path, events_json, event_count, evidence_id=None):
        analyzed_at = self._now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO log_analyses (evidence_id, source_path, events_json, analyzed_at)
                VALUES (?, ?, ?, ?)
                """,
                (evidence_id, source_path, events_json, analyzed_at),
            )
            self.log_activity(
                connection,
                "Log analyzed",
                "{} ({} events)".format(Path(source_path).name, event_count),
            )
            return cursor.lastrowid

    def list_log_analyses(self, limit=50):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT log_analyses.*, evidence.name AS evidence_name
                FROM log_analyses
                LEFT JOIN evidence ON evidence.id = log_analyses.evidence_id
                ORDER BY analyzed_at DESC, log_analyses.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    def list_integrity_checks(self, limit=100):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT integrity_checks.*, evidence.name AS evidence_name,
                       evidence.path AS evidence_path
                FROM integrity_checks
                JOIN evidence ON evidence.id = integrity_checks.evidence_id
                ORDER BY integrity_checks.checked_at DESC, integrity_checks.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    def record_report(self, case_id, path, report_format):
        generated_at = self._now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reports (case_id, path, format, generated_at)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, path, report_format, generated_at),
            )
            self.log_activity(connection, "Report generated", Path(path).name)

    def count(self, table):
        if table not in {"cases", "evidence", "custody", "activity", "integrity_checks", "reports"}:
            raise ValueError("Unsupported table name")
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

    @staticmethod
    def log_activity(connection, action, details):
        connection.execute(
            "INSERT INTO activity (action, details, created_at) VALUES (?, ?, ?)",
            (action, details, Database._now()),
        )
