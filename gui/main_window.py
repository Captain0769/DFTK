from PyQt5.QtCore import QObject, QThread, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont
from datetime import datetime
import csv
import json
import os
import sqlite3
from pathlib import Path
from threading import Event
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressDialog,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDateEdit,
    QFormLayout,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.database import Database
from core.hashing import ALGORITHMS, compare_hashes, hash_file
from core.metadata import extract_metadata
from core.log_analysis import SEVERITIES, parse_log
from core.exports import export_json, export_pdf, export_rows_csv
from core.timeline import filter_events, sort_events
from core.filesystem_analysis import scan_directory


ACCENT = "#4f8cff"
BACKGROUND = "#111827"
PANEL = "#1b2536"
PANEL_LIGHT = "#243149"
TEXT = "#f3f4f6"
MUTED = "#9ca3af"


class HashWorker(QObject):
    completed = pyqtSignal(int, object)
    failed = pyqtSignal(int, str)

    def __init__(self, evidence_id, path):
        super().__init__()
        self.evidence_id = evidence_id
        self.path = path

    @pyqtSlot()
    def run(self):
        try:
            self.completed.emit(self.evidence_id, hash_file(self.path))
        except OSError as error:
            self.failed.emit(self.evidence_id, str(error))


class FileSystemScanWorker(QObject):
    completed = pyqtSignal(object, object, bool)
    failed = pyqtSignal(str)

    def __init__(self, root, cancel_event):
        super().__init__()
        self.root = root
        self.cancel_event = cancel_event

    @pyqtSlot()
    def run(self):
        try:
            records, errors = scan_directory(self.root, self.cancel_event)
            self.completed.emit(records, errors, self.cancel_event.is_set())
        except (OSError, ValueError) as error:
            self.failed.emit(str(error))


class MetadataWorker(QObject):
    completed = pyqtSignal(object, object, object)
    failed = pyqtSignal(object, str, str)

    def __init__(self, path, evidence_id):
        super().__init__()
        self.path = path
        self.evidence_id = evidence_id

    @pyqtSlot()
    def run(self):
        try:
            self.completed.emit(
                self.evidence_id, self.path, extract_metadata(self.path)
            )
        except (OSError, ValueError) as error:
            self.failed.emit(self.evidence_id, self.path, str(error))


class LogAnalysisWorker(QObject):
    completed = pyqtSignal(str, object, object)
    failed = pyqtSignal(str, str)

    def __init__(self, path, evidence_id):
        super().__init__()
        self.path = path
        self.evidence_id = evidence_id

    @pyqtSlot()
    def run(self):
        try:
            self.completed.emit(self.path, parse_log(self.path), self.evidence_id)
        except (OSError, ValueError, csv.Error) as error:
            self.failed.emit(self.path, str(error))


class MainWindow(QMainWindow):
    """Main application shell for the AMAAN Digital Forensic Toolkit."""

    PAGES = [
        ("Dashboard", "Overview of your current investigation"),
        ("Evidence Management", "Organize cases and evidence items"),
        ("Hashing & Integrity", "Verify evidence with cryptographic hashes"),
        ("File System Analysis", "Inspect files, folders, and file systems"),
        ("Metadata Analysis", "Review timestamps and file metadata"),
        ("Log Analysis", "Search and analyze forensic log data"),
        ("Timeline Analysis", "Build a chronological view of investigation activity"),
        ("Global Search", "Search cases, evidence, hashes, and activity"),
    ]

    def __init__(self):
        super().__init__()
        self.database = Database()
        self.setWindowTitle("DFTK - Digital Forensic Toolkit")
        self.resize(1280, 760)
        self.setMinimumSize(1000, 620)
        self.dark_theme = True
        self.hash_thread = None
        self.hash_worker = None
        self.filesystem_thread = None
        self.filesystem_worker = None
        self.filesystem_cancel = None
        self.metadata_thread = None
        self.metadata_worker = None
        self.log_thread = None
        self.log_worker = None
        self._set_style()
        self._build_ui()

    def _set_style(self):
        if self.dark_theme:
            background, sidebar, panel, panel_alt = "#111827", "#151f2e", "#1b2536", "#243149"
            text, muted, border, input_bg = "#f3f4f6", "#9ca3af", "#334155", "#0f172a"
        else:
            background, sidebar, panel, panel_alt = "#f8fafc", "#e2e8f0", "#ffffff", "#eef2ff"
            text, muted, border, input_bg = "#0f172a", "#475569", "#cbd5e1", "#f1f5f9"
        self.setStyleSheet(
            """
            QMainWindow, QWidget {{ background: {background}; color: {text}; }}
            QLabel {{ color: {text}; background: transparent; }}
            QFrame#sidebar {{ background: {sidebar}; }}
            QFrame#panel, QFrame#statCard {{ background: {panel}; border: 1px solid {border}; border-radius: 9px; }}
            QLabel#muted, QLabel#pageSubtitle, QLabel#statusLabel {{ color: {muted}; }}
            QLabel#brand {{ color: #4f8cff; }}
            QListWidget {{
                background: {sidebar}; border: none; padding: 14px 8px;
                outline: none;
            }}
            QListWidget#caseSelector {{ padding: 0; }}
            QListWidget#caseSelector::item {{ padding: 7px 10px; margin: 0; }}
            QListWidget::item {{
                color: {muted}; padding: 10px 14px; margin: 3px 0;
                border-radius: 7px;
            }}
            QListWidget::item:selected {{
                background: {panel_alt}; color: {text};
                border-left: 3px solid #4f8cff;
            }}
            QPushButton {{
                background: #4f8cff; color: white; border: none;
                border-radius: 6px; padding: 10px 16px; font-weight: 600;
            }}
            QPushButton:hover {{ background: #6b9cff; }}
            QPushButton:disabled {{ background: {panel_alt}; color: {muted}; }}
            QLineEdit, QComboBox {{
                background: {input_bg}; color: {text}; border: 1px solid {border};
                border-radius: 5px; padding: 7px 9px; min-height: 18px;
            }}
            QComboBox QAbstractItemView {{ background: {panel}; color: {text}; selection-background-color: #4f8cff; }}
            QCheckBox {{ color: {text}; spacing: 6px; }}
            QTableWidget {{
                background: {panel}; alternate-background-color: {input_bg};
                color: {text}; border: 1px solid {border}; gridline-color: {border};
                selection-background-color: {panel_alt}; selection-color: {text};
            }}
            QHeaderView::section {{
                background: {panel_alt}; color: {text}; border: none;
                border-right: 1px solid {border}; border-bottom: 1px solid {border};
                padding: 8px; font-weight: 600;
            }}
            QProgressBar {{
                background: {input_bg}; border: none; border-radius: 4px;
                height: 8px; text-align: center;
            }}
            QProgressBar::chunk {{ background: #4f8cff; border-radius: 4px; }}
            QScrollBar:vertical {{ background: {input_bg}; width: 10px; margin: 0; }}
            QScrollBar::handle:vertical {{ background: {border}; min-height: 24px; border-radius: 5px; }}
            QScrollBar:horizontal {{ background: {input_bg}; height: 10px; margin: 0; }}
            QScrollBar::handle:horizontal {{ background: {border}; min-width: 24px; border-radius: 5px; }}
            """
            .format(
                background=background, sidebar=sidebar, panel=panel, panel_alt=panel_alt,
                text=text, muted=muted, border=border, input_bg=input_bg
            )
        )

    def _build_ui(self):
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(34, 28, 34, 24)
        content_layout.setSpacing(18)
        self.page_title = QLabel()
        self.page_title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self.page_subtitle = QLabel()
        self.page_subtitle.setObjectName("pageSubtitle")
        content_layout.addWidget(self.page_title)
        content_layout.addWidget(self.page_subtitle)

        self.pages = QStackedWidget()
        self.page_scroll_areas = []
        for index, (title, subtitle) in enumerate(self.PAGES):
            if index == 0:
                page = self._dashboard_page()
            elif index == 1:
                page = self._evidence_page()
            elif index == 2:
                page = self._hashing_page()
            elif index == 3:
                page = self._filesystem_page()
            elif index == 4:
                page = self._metadata_page()
            elif index == 5:
                page = self._log_page()
            elif index == 6:
                page = self._timeline_page()
            elif index == 7:
                page = self._search_page()
            else:
                page = self._module_page(title)
            page_scroll = QScrollArea()
            page_scroll.setWidgetResizable(True)
            page_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            page_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            page_scroll.setFrameShape(QFrame.NoFrame)
            page_scroll.setWidget(page)
            self.page_scroll_areas.append(page_scroll)
            self.pages.addWidget(page_scroll)
        content_layout.addWidget(self.pages, 1)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(root)
        self._select_page(0)

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(260)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(20, 26, 20, 20)
        layout.setSpacing(10)

        brand = QLabel("DFTK")
        brand.setObjectName("brand")
        brand.setFont(QFont("Segoe UI", 24, QFont.Bold))
        brand.setStyleSheet("color: #4f8cff;")
        tagline = QLabel("Digital Forensic Toolkit")
        tagline.setObjectName("muted")
        layout.addWidget(brand)
        layout.addWidget(tagline)
        layout.addSpacing(24)

        self.navigation = QListWidget()
        self.navigation.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        for title, _subtitle in self.PAGES:
            self.navigation.addItem(QListWidgetItem(title))
        self.navigation.currentRowChanged.connect(self._select_page)
        layout.addWidget(self.navigation)

        version = QLabel("DFTK v1.0  |  Investigation workspace")
        version.setObjectName("muted")
        version.setStyleSheet("font-size: 11px;")
        layout.addWidget(version)
        theme = QPushButton("Switch to light theme")
        theme.clicked.connect(self._toggle_theme)
        layout.addWidget(theme)
        self.theme_button = theme
        return sidebar

    def _toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self._set_style()
        self.theme_button.setText(
            "Switch to light theme" if self.dark_theme else "Switch to dark theme"
        )

    def _select_page(self, index):
        if index < 0 or index >= len(self.PAGES):
            return
        title, subtitle = self.PAGES[index]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        self.pages.setCurrentIndex(index)
        if index == 0:
            self._refresh_dashboard()
        if self.navigation.currentRow() != index:
            self.navigation.setCurrentRow(index)

    def _dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(14)
        welcome = QLabel("Investigation overview")
        welcome.setFont(QFont("Segoe UI", 15, QFont.Bold))
        heading_row = QHBoxLayout()
        heading_row.addWidget(welcome)
        heading_row.addStretch()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self._refresh_dashboard)
        heading_row.addWidget(refresh_button)
        layout.addLayout(heading_row)

        cards = QGridLayout()
        cards.setSpacing(14)
        self.dashboard_values = {}
        for position, (label, value, color) in enumerate(
            [
                ("Open Cases", "0", "#4f8cff"),
                ("Evidence Items", "0", "#22c55e"),
                ("Integrity Checks", "0", "#f59e0b"),
                ("Reports Generated", "0", "#a78bfa"),
            ]
        ):
            card = self._stat_card(label, value, color)
            self.dashboard_values[label] = card.findChildren(QLabel)[1]
            cards.addWidget(card, 0, position)
        layout.addLayout(cards)

        actions = QHBoxLayout()
        actions.addWidget(self._dashboard_action("Create case", self._dashboard_create_case))
        actions.addWidget(self._dashboard_action("Add evidence", self._dashboard_add_evidence))
        actions.addWidget(self._dashboard_action("Analyze files", lambda: self.navigation.setCurrentRow(3)))
        actions.addWidget(self._dashboard_action("Generate report", self._generate_case_report))
        layout.addLayout(actions)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        activity_panel = self._dashboard_table_panel("Recent activity")
        activity_layout = activity_panel.layout()
        self.dashboard_activity_table = QTableWidget(0, 3)
        self.dashboard_activity_table.setHorizontalHeaderLabels(["Activity", "Details", "When"])
        self.dashboard_activity_table.setAlternatingRowColors(True)
        self.dashboard_activity_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dashboard_activity_table.verticalHeader().setVisible(False)
        self.dashboard_activity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.dashboard_activity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dashboard_activity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        activity_layout.addWidget(self.dashboard_activity_table)

        cases_panel = self._dashboard_table_panel("Recent cases")
        cases_layout = cases_panel.layout()
        self.dashboard_cases_table = QTableWidget(0, 4)
        self.dashboard_cases_table.setHorizontalHeaderLabels(["Case", "Status", "Evidence", "Investigator"])
        self.dashboard_cases_table.setAlternatingRowColors(True)
        self.dashboard_cases_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dashboard_cases_table.verticalHeader().setVisible(False)
        self.dashboard_cases_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for column in (1, 2, 3):
            self.dashboard_cases_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeToContents
            )
        self.dashboard_cases_table.cellDoubleClicked.connect(self._open_case_from_dashboard)
        cases_layout.addWidget(self.dashboard_cases_table)

        lower.addWidget(activity_panel, 1)
        lower.addWidget(cases_panel, 1)
        layout.addLayout(lower)
        layout.addStretch()
        self._refresh_dashboard()
        return page

    def _dashboard_table_panel(self, title):
        panel = QFrame()
        panel.setObjectName("panel")
        panel.setMinimumHeight(260)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 14, 16, 14)
        heading = QLabel(title)
        heading.setFont(QFont("Segoe UI", 13, QFont.Bold))
        panel_layout.addWidget(heading)
        return panel

    @staticmethod
    def _dashboard_action(label, callback):
        button = QPushButton(label)
        button.setMinimumHeight(40)
        button.clicked.connect(callback)
        return button

    def _dashboard_create_case(self):
        self.navigation.setCurrentRow(1)
        self._create_case()

    def _dashboard_add_evidence(self):
        self.navigation.setCurrentRow(1)
        self._add_evidence()

    def _open_case_from_dashboard(self, row, _column):
        case_id = self.dashboard_cases_table.item(row, 0).data(Qt.UserRole)
        for index in range(self.case_selector.count()):
            if self.case_selector.itemData(index) == case_id:
                self.case_selector.setCurrentIndex(index)
                self.navigation.setCurrentRow(1)
                return

    def _refresh_dashboard(self):
        if not hasattr(self, "dashboard_values"):
            return
        summary = self.database.dashboard_summary()
        self.dashboard_values["Open Cases"].setText(str(summary["open_cases"]))
        self.dashboard_values["Evidence Items"].setText(str(summary["evidence"]))
        self.dashboard_values["Integrity Checks"].setText(str(summary["integrity_checks"]))
        self.dashboard_values["Reports Generated"].setText(str(summary["reports"]))

        self.dashboard_activity_table.setRowCount(0)
        for activity in self.database.list_activity(limit=8):
            row = self.dashboard_activity_table.rowCount()
            self.dashboard_activity_table.insertRow(row)
            for column, key in enumerate(("action", "details", "created_at")):
                value = str(activity[key] or "")
                if key == "created_at":
                    value = value.replace("T", " ")[:16]
                self.dashboard_activity_table.setItem(row, column, QTableWidgetItem(value))

        self.dashboard_cases_table.setRowCount(0)
        for case in self.database.list_recent_cases(limit=8):
            row = self.dashboard_cases_table.rowCount()
            self.dashboard_cases_table.insertRow(row)
            case_item = QTableWidgetItem(case["name"])
            case_item.setData(Qt.UserRole, case["id"])
            values = [case_item, QTableWidgetItem(case["status"]),
                      QTableWidgetItem(str(case["evidence_count"])),
                      QTableWidgetItem(case["investigator"])]
            for column, item in enumerate(values):
                self.dashboard_cases_table.setItem(row, column, item)

    def _generate_case_report(self):
        cases = self.database.list_cases()
        if not cases:
            QMessageBox.information(self, "No cases", "Create a case before generating a report.")
            return
        case = cases[0]
        if len(cases) > 1:
            labels = [
                "{} - {} - {}".format(item["name"], item["status"], item["created_at"][:10])
                for item in cases
            ]
            selected, accepted = QInputDialog.getItem(
                self, "Select case", "Generate report for:", labels, 0, False
            )
            if not accepted:
                return
            case = cases[labels.index(selected)]
        evidence = self.database.list_evidence(case["id"])
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save case report",
            "dftk_case_report.pdf",
            "PDF report (*.pdf);;JSON report (*.json)",
        )
        if not path:
            return
        payload = {
            "case": dict(case),
            "evidence": [dict(item) for item in evidence],
            "custody": [
                dict(record)
                for item in evidence
                for record in self.database.list_custody(item["id"])
            ],
            "timeline": [dict(event) for event in self.database.list_timeline()],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            if path.lower().endswith(".json") or "JSON" in selected_filter:
                export_json(path, payload)
                report_format = "JSON"
            else:
                export_pdf(
                    path,
                    "DFTK Case Report - {}".format(case["name"]),
                    [
                        ("Case information", [
                            "Investigator: {}".format(case["investigator"]),
                            "Status: {}".format(case["status"]),
                            "Created: {}".format(case["created_at"]),
                        ]),
                        ("Evidence", [
                            "{} | {} | SHA-256 {}".format(
                                item["name"], item["path"], item["sha256"]
                            )
                            for item in evidence
                        ]),
                        ("Chain of custody", [
                            "{} | {} | {} | {}".format(
                                record["created_at"], record["action"],
                                record["actor"], record["notes"]
                            )
                            for item in evidence
                            for record in self.database.list_custody(item["id"])
                        ]),
                    ],
                )
                report_format = "PDF"
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, "Report generation failed", str(error))
            return
        self.database.record_report(case["id"], path, report_format)
        self._refresh_dashboard()
        self.statusBar().showMessage("Case report exported.", 5000)

    def _evidence_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(12)
        case_controls = QHBoxLayout()
        self.case_selector = QComboBox()
        self.case_selector.setMinimumWidth(260)
        self.case_selector.currentIndexChanged.connect(self._load_evidence)
        new_case = QPushButton("New case")
        new_case.clicked.connect(self._create_case)
        edit_case = QPushButton("Edit case")
        edit_case.clicked.connect(self._edit_case)
        status = QPushButton("Update status")
        status.clicked.connect(self._update_case_status)
        case_controls.addWidget(QLabel("Active case:"))
        case_controls.addWidget(self.case_selector, 1)
        case_controls.addWidget(new_case)
        case_controls.addWidget(edit_case)
        case_controls.addWidget(status)
        layout.addLayout(case_controls)

        evidence_controls = QHBoxLayout()
        add_evidence = QPushButton("Add evidence")
        add_evidence.clicked.connect(self._add_evidence)
        add_folder = QPushButton("Add folder")
        add_folder.clicked.connect(self._add_evidence_folder)
        custody = QPushButton("Chain of custody")
        custody.clicked.connect(self._show_custody)
        export = QPushButton("Export CSV")
        export.clicked.connect(self._export_evidence_csv)
        evidence_controls.addWidget(add_evidence)
        evidence_controls.addWidget(add_folder)
        evidence_controls.addWidget(custody)
        evidence_controls.addWidget(export)
        evidence_controls.addStretch()
        layout.addLayout(evidence_controls)

        self.evidence_search = QLineEdit()
        self.evidence_search.setPlaceholderText("Filter evidence by name, type, hash, or path...")
        self.evidence_search.textChanged.connect(self._filter_evidence)
        layout.addWidget(self.evidence_search)
        self.evidence_status = QLabel("Select or create a case to manage evidence.")
        self.evidence_status.setObjectName("statusLabel")
        layout.addWidget(self.evidence_status)

        self.evidence_table = QTableWidget(0, 6)
        self.evidence_table.setHorizontalHeaderLabels(
            ["Name", "Type", "Size (bytes)", "SHA-256", "Added", "Path"]
        )
        self.evidence_table.horizontalHeader().setStretchLastSection(True)
        self.evidence_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.setSelectionMode(QTableWidget.SingleSelection)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.verticalHeader().setVisible(False)
        layout.addWidget(self.evidence_table)
        self._current_case_evidence = []
        self._load_cases()
        return page

    def _load_cases(self):
        selected_case_id = self._selected_case_id()
        self.case_selector.blockSignals(True)
        self.case_selector.clear()
        for case in self.database.list_cases():
            self.case_selector.addItem(
                "{}  |  {}".format(case["name"], case["status"]), case["id"]
            )
        if selected_case_id is not None:
            selected_index = self.case_selector.findData(selected_case_id)
            if selected_index >= 0:
                self.case_selector.setCurrentIndex(selected_index)
        if self.case_selector.currentIndex() < 0 and self.case_selector.count():
            self.case_selector.setCurrentIndex(0)
        self.case_selector.blockSignals(False)
        self._load_evidence(self.case_selector.currentIndex())

    def _selected_case_id(self):
        if not hasattr(self, "case_selector"):
            return None
        case_id = self.case_selector.currentData()
        return int(case_id) if case_id is not None else None

    def _show_case_dialog(self, title, name="", description="", investigator=""):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(420)
        form = QFormLayout(dialog)
        name_input = QLineEdit(name)
        description_input = QPlainTextEdit(description)
        description_input.setMaximumHeight(110)
        investigator_input = QLineEdit(investigator)
        form.addRow("Case name:", name_input)
        form.addRow("Description:", description_input)
        form.addRow("Investigator:", investigator_input)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec_() != QDialog.Accepted:
            return None
        case_name = name_input.text().strip()
        if not case_name:
            QMessageBox.warning(self, "Case name required", "Enter a name for this case.")
            return None
        return (
            case_name,
            description_input.toPlainText().strip(),
            investigator_input.text().strip(),
        )

    def _create_case(self):
        details = self._show_case_dialog("Create case")
        if details is None:
            return
        name, description, investigator = details
        case_id = self.database.create_case(name, description, investigator)
        self._load_cases()
        self.case_selector.setCurrentIndex(self.case_selector.findData(case_id))
        self._refresh_dashboard()
        self.statusBar().showMessage("Case created: {}".format(name), 5000)

    def _edit_case(self):
        case_id = self._selected_case_id()
        if case_id is None:
            QMessageBox.information(self, "No case selected", "Create or select a case first.")
            return
        case = next(item for item in self.database.list_cases() if item["id"] == case_id)
        details = self._show_case_dialog(
            "Edit case", case["name"], case["description"], case["investigator"]
        )
        if details is None:
            return
        self.database.update_case_details(case_id, *details)
        self._load_cases()
        self._refresh_dashboard()
        self.statusBar().showMessage("Case details updated.", 5000)

    def _load_evidence(self, _index):
        self.evidence_table.setRowCount(0)
        case_id = self._selected_case_id()
        if case_id is None:
            self._current_case_evidence = []
            self.evidence_status.setText("No cases yet. Create a case to register evidence.")
            return
        self._current_case_evidence = self.database.list_evidence(case_id)
        for evidence in self._current_case_evidence:
            values = [
                evidence["name"],
                evidence["evidence_type"],
                str(evidence["size"]),
                evidence["sha256"][:16] + "...",
                evidence["created_at"],
                evidence["path"],
            ]
            table_row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(table_row)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, evidence["id"])
                if column == 5:
                    item.setToolTip(value)
                self.evidence_table.setItem(table_row, column, item)
        self._filter_evidence()

    def _add_evidence(self):
        case_id = self._selected_case_id()
        if case_id is None:
            QMessageBox.information(self, "Select a case", "Create or select a case first.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Select evidence file")
        if not path:
            return
        try:
            evidence_path = Path(path)
            if self.database.has_evidence_path(case_id, evidence_path):
                QMessageBox.information(
                    self,
                    "Evidence already registered",
                    "This path is already registered under the selected case.",
                )
                return
            hashes = hash_file(evidence_path)
            self.database.add_evidence(
                case_id,
                evidence_path.name,
                str(evidence_path),
                "File",
                evidence_path.stat().st_size,
                hashes,
            )
        except (OSError, PermissionError) as error:
            QMessageBox.critical(self, "Evidence error", str(error))
            return
        self._load_evidence(self.case_selector.currentIndex())
        self._load_hash_evidence()
        self._refresh_dashboard()
        self.statusBar().showMessage("Evidence hashed and added.", 5000)

    def _add_evidence_folder(self):
        case_id = self._selected_case_id()
        if case_id is None:
            QMessageBox.information(self, "Select a case", "Create or select a case first.")
            return
        path = QFileDialog.getExistingDirectory(self, "Select evidence folder")
        if not path:
            return
        root = Path(path)
        added, failed = 0, 0
        duplicates = 0
        errors = []
        progress = QProgressDialog(
            "Scanning and hashing evidence files...", "Cancel", 0, 0, self
        )
        progress.setWindowTitle("Adding evidence folder")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(500)
        progress.show()
        existing_paths = {
            str(Path(item["path"]).resolve()).casefold()
            for item in self.database.list_evidence(case_id)
        }
        try:
            for item in root.rglob("*"):
                QApplication.processEvents()
                if progress.wasCanceled():
                    break
                if not item.is_file():
                    continue
                try:
                    normalized_path = str(item.resolve()).casefold()
                    if normalized_path in existing_paths:
                        duplicates += 1
                        continue
                    self.database.add_evidence(
                        case_id,
                        item.name,
                        str(item),
                        "Folder file",
                        item.stat().st_size,
                        hash_file(item),
                    )
                    existing_paths.add(normalized_path)
                    added += 1
                except OSError as error:
                    failed += 1
                    if len(errors) < 5:
                        errors.append("{}: {}".format(item, error))
        except OSError as error:
            progress.close()
            QMessageBox.critical(self, "Folder scan failed", str(error))
            return
        progress.close()
        self._load_evidence(self.case_selector.currentIndex())
        self._load_hash_evidence()
        self._refresh_dashboard()
        result = "{} added, {} duplicates skipped, {} unreadable.".format(
            added, duplicates, failed
        )
        if progress.wasCanceled():
            result += " Import cancelled."
        self.evidence_status.setText(result)
        if errors:
            QMessageBox.warning(
                self, "Some files were skipped", result + "\n\n" + "\n".join(errors)
            )

    def _update_case_status(self):
        case_id = self._selected_case_id()
        if case_id is None:
            return
        status, accepted = QInputDialog.getItem(
            self, "Case status", "Status:", ["Open", "In progress", "Closed"], 0, False
        )
        if accepted:
            self.database.update_case_status(
                case_id, status
            )
            self._load_cases()
            self._refresh_dashboard()

    def _show_custody(self):
        row = self.evidence_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select evidence", "Select an evidence row first.")
            return
        evidence_id = self.evidence_table.item(row, 0).data(Qt.UserRole)
        evidence = next(
            (item for item in self._current_case_evidence if item["id"] == evidence_id),
            None,
        )
        if evidence is None:
            QMessageBox.warning(self, "Evidence unavailable", "Reload the case and try again.")
            return
        records = self.database.list_custody(evidence["id"])
        dialog = QDialog(self)
        dialog.setWindowTitle("Chain of custody - {}".format(evidence["name"]))
        dialog.resize(760, 380)
        dialog_layout = QVBoxLayout(dialog)
        custody_table = QTableWidget(len(records), 4)
        custody_table.setHorizontalHeaderLabels(["Timestamp", "Action", "Actor", "Notes"])
        for column in range(3):
            custody_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeToContents
            )
        custody_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        custody_table.setEditTriggers(QTableWidget.NoEditTriggers)
        for record_row, record in enumerate(records):
            for column, key in enumerate(("created_at", "action", "actor", "notes")):
                custody_table.setItem(
                    record_row, column, QTableWidgetItem(str(record[key] or ""))
                )
        dialog_layout.addWidget(custody_table)
        buttons = QHBoxLayout()
        add_record = QPushButton("Record custody event")
        add_record.clicked.connect(
            lambda: self._add_custody_event(evidence["id"], dialog)
        )
        close = QPushButton("Close")
        close.clicked.connect(dialog.accept)
        buttons.addWidget(add_record)
        buttons.addStretch()
        buttons.addWidget(close)
        dialog_layout.addLayout(buttons)
        dialog.exec_()

    def _add_custody_event(self, evidence_id, dialog):
        action, accepted = QInputDialog.getItem(
            dialog, "Custody event", "Event:",
            ["Transferred", "Accessed", "Sealed", "Released", "Returned", "Other"],
            0, False,
        )
        if not accepted:
            return
        actor, accepted = QInputDialog.getText(
            dialog, "Custody event", "Person responsible:"
        )
        if not accepted or not actor.strip():
            return
        notes, accepted = QInputDialog.getMultiLineText(
            dialog, "Custody event", "Notes:"
        )
        if not accepted:
            return
        self.database.add_custody(evidence_id, action, actor.strip(), notes.strip())
        self._refresh_dashboard()
        dialog.accept()
        self._show_custody_for_id(evidence_id)

    def _show_custody_for_id(self, evidence_id):
        for row in range(self.evidence_table.rowCount()):
            if self.evidence_table.item(row, 0).data(Qt.UserRole) == evidence_id:
                self.evidence_table.selectRow(row)
                self._show_custody()
                return

    def _export_evidence_csv(self):
        case_id = self._selected_case_id()
        if case_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export evidence CSV", "", "CSV files (*.csv)")
        if not path:
            return
        evidence = self.database.list_evidence(case_id)
        export_rows_csv(
            path,
            ["Name", "Path", "Type", "Size", "MD5", "SHA1", "SHA256", "SHA512"],
            [
                [item[key] for key in ("name", "path", "evidence_type", "size", "md5", "sha1", "sha256", "sha512")]
                for item in evidence
            ],
        )
        self.statusBar().showMessage("Evidence CSV exported.", 5000)

    def _filter_evidence(self, _query=""):
        if not hasattr(self, "evidence_table"):
            return
        query = self.evidence_search.text().strip().lower()
        visible = 0
        for row in range(self.evidence_table.rowCount()):
            cells = [
                self.evidence_table.item(row, column).text().lower()
                for column in range(self.evidence_table.columnCount())
            ]
            matches = not query or any(query in value for value in cells)
            self.evidence_table.setRowHidden(row, not matches)
            visible += int(matches)
        self.evidence_status.setText(
            "{} of {} evidence item(s) shown.".format(
                visible, len(self._current_case_evidence)
            )
        )

    def _hashing_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        self.hash_evidence_selector = QComboBox()
        self.hash_evidence_selector.setMinimumWidth(300)
        self.hash_evidence_selector.currentIndexChanged.connect(
            self._show_selected_hashes
        )
        refresh = QPushButton("Refresh evidence")
        refresh.clicked.connect(self._load_hash_evidence)
        self.verify_button = QPushButton("Verify selected file")
        self.verify_button.clicked.connect(self._verify_selected_evidence)
        controls.addWidget(QLabel("Evidence:"))
        controls.addWidget(self.hash_evidence_selector, 1)
        controls.addWidget(refresh)
        controls.addWidget(self.verify_button)
        layout.addLayout(controls)

        self.hash_status = QLabel("Select registered evidence to view and verify its hashes.")
        self.hash_status.setObjectName("statusLabel")
        layout.addWidget(self.hash_status)

        self.hash_progress = QProgressBar()
        self.hash_progress.setRange(0, 0)
        self.hash_progress.setTextVisible(False)
        self.hash_progress.hide()
        layout.addWidget(self.hash_progress)

        self.hash_table = QTableWidget(0, 4)
        self.hash_table.setHorizontalHeaderLabels(
            ["Algorithm", "Recorded digest", "Current digest", "Result"]
        )
        self.hash_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.hash_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.hash_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.hash_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.hash_table.setAlternatingRowColors(True)
        self.hash_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.hash_table.verticalHeader().setVisible(False)
        layout.addWidget(self.hash_table)

        history_heading = QLabel("Verification history")
        history_heading.setFont(QFont("Segoe UI", 13, QFont.Bold))
        layout.addWidget(history_heading)
        self.integrity_history = QTableWidget(0, 4)
        self.integrity_history.setHorizontalHeaderLabels(
            ["Checked at", "Evidence", "Result", "Algorithms"]
        )
        self.integrity_history.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.integrity_history.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self.integrity_history.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        self.integrity_history.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeToContents
        )
        self.integrity_history.setAlternatingRowColors(True)
        self.integrity_history.setEditTriggers(QTableWidget.NoEditTriggers)
        self.integrity_history.verticalHeader().setVisible(False)
        layout.addWidget(self.integrity_history)
        self._load_hash_evidence()
        self._load_integrity_history()
        return page

    def _load_hash_evidence(self):
        if not hasattr(self, "hash_evidence_selector"):
            return
        selected_id = self.hash_evidence_selector.currentData()
        self.hash_evidence_selector.blockSignals(True)
        self.hash_evidence_selector.clear()
        for evidence in self.database.list_all_evidence():
            label = "{}  |  {}  |  {}".format(
                evidence["name"], evidence["case_name"], evidence["path"]
            )
            self.hash_evidence_selector.addItem(label, evidence["id"])
        self.hash_evidence_selector.blockSignals(False)
        if selected_id is not None:
            index = self.hash_evidence_selector.findData(selected_id)
            if index >= 0:
                self.hash_evidence_selector.setCurrentIndex(index)
        if self.hash_evidence_selector.currentIndex() < 0 and self.hash_evidence_selector.count():
            self.hash_evidence_selector.setCurrentIndex(0)
        self._show_selected_hashes(self.hash_evidence_selector.currentIndex())

    def _selected_evidence(self):
        evidence_id = self.hash_evidence_selector.currentData()
        if evidence_id is None:
            return None
        return next(
            (
                evidence for evidence in self.database.list_all_evidence()
                if evidence["id"] == evidence_id
            ),
            None,
        )

    def _show_selected_hashes(self, _index):
        self.hash_table.setRowCount(0)
        evidence = self._selected_evidence()
        if evidence is None:
            self.hash_status.setText("No registered evidence is available to verify.")
            return
        self.hash_status.setText(
            "Recorded hashes for {}. Run verification to compare against the source file.".format(
                evidence["name"]
            )
        )
        for algorithm in ALGORITHMS:
            row = self.hash_table.rowCount()
            self.hash_table.insertRow(row)
            self.hash_table.setItem(row, 0, QTableWidgetItem(algorithm.upper()))
            self.hash_table.setItem(
                row, 1, QTableWidgetItem(evidence[algorithm] or "(not recorded)")
            )
            self.hash_table.setItem(row, 2, QTableWidgetItem("Not checked"))
            self.hash_table.setItem(row, 3, QTableWidgetItem("Not checked"))
        self._load_integrity_history()

    def _verify_selected_evidence(self):
        evidence = self._selected_evidence()
        if evidence is None:
            QMessageBox.information(self, "No evidence", "Add evidence before verifying it.")
            return
        if self.hash_thread is not None and self.hash_thread.isRunning():
            return
        self.hash_status.setText("Calculating hashes. Large evidence files may take time...")
        self.hash_status.setStyleSheet("color: #4f8cff; font-weight: 600;")
        self.hash_progress.show()
        self.verify_button.setEnabled(False)
        self.hash_thread = QThread(self)
        self.hash_worker = HashWorker(evidence["id"], evidence["path"])
        self.hash_worker.moveToThread(self.hash_thread)
        self.hash_thread.started.connect(self.hash_worker.run)
        self.hash_worker.completed.connect(self._on_hash_verification_complete)
        self.hash_worker.failed.connect(self._on_hash_verification_failed)
        self.hash_worker.completed.connect(self.hash_thread.quit, Qt.DirectConnection)
        self.hash_worker.failed.connect(self.hash_thread.quit, Qt.DirectConnection)
        self.hash_thread.finished.connect(self.hash_worker.deleteLater)
        self.hash_thread.finished.connect(self._on_hash_thread_finished)
        self.hash_thread.start()

    def _on_hash_verification_complete(self, evidence_id, current_hashes):
        evidence = next(
            (
                item for item in self.database.list_all_evidence()
                if item["id"] == evidence_id
            ),
            None,
        )
        if evidence is None:
            self.hash_status.setText("Evidence record no longer exists; refresh and try again.")
            return
        status, comparisons = compare_hashes(evidence, current_hashes)
        if self.hash_evidence_selector.currentData() == evidence_id:
            for row, algorithm in enumerate(ALGORITHMS):
                self.hash_table.setItem(row, 2, QTableWidgetItem(current_hashes[algorithm]))
                self.hash_table.setItem(
                    row, 3, QTableWidgetItem(comparisons[algorithm].upper())
                )
        details = json.dumps(comparisons, sort_keys=True)
        self.database.record_integrity_check(evidence["id"], status, details)
        if status == "Verified":
            result_text = "INTEGRITY VERIFIED — all recorded algorithm digests match."
            result_color = "#22c55e"
        else:
            result_text = "INTEGRITY MISMATCH — one or more digests differ or were not recorded."
            result_color = "#ef4444"
        if self.hash_evidence_selector.currentData() == evidence_id:
            self.hash_status.setText(result_text)
            self.hash_status.setStyleSheet("color: {}; font-weight: 600;".format(result_color))
        self._load_integrity_history()
        self._refresh_dashboard()

    def _on_hash_verification_failed(self, evidence_id, message):
        evidence = next(
            (
                item for item in self.database.list_all_evidence()
                if item["id"] == evidence_id
            ),
            None,
        )
        if evidence is not None:
            self.database.record_integrity_check(
                evidence["id"], "Unavailable", json.dumps({"error": message})
            )
            self._load_integrity_history()
            self._refresh_dashboard()
        self.hash_status.setText("Could not read the registered evidence file.")
        self.hash_status.setStyleSheet("color: #ef4444; font-weight: 600;")
        QMessageBox.critical(self, "Verification error", message)

    def _on_hash_thread_finished(self):
        self.hash_progress.hide()
        self.verify_button.setEnabled(True)
        self.hash_thread = None
        self.hash_worker = None

    def closeEvent(self, event):
        if self.hash_thread is not None and self.hash_thread.isRunning():
            self.statusBar().showMessage(
                "Hash verification is still running. Wait for it to finish before closing."
            )
            event.ignore()
            return
        if self.metadata_thread is not None and self.metadata_thread.isRunning():
            self.statusBar().showMessage(
                "Metadata analysis is still running. Wait for it to finish before closing."
            )
            event.ignore()
            return
        if self.log_thread is not None and self.log_thread.isRunning():
            self.statusBar().showMessage(
                "Log analysis is still running. Wait for it to finish before closing."
            )
            event.ignore()
            return
        if self.filesystem_thread is not None and self.filesystem_thread.isRunning():
            if self.filesystem_cancel is not None:
                self.filesystem_cancel.set()
            self.statusBar().showMessage(
                "File-system scan is stopping. Close the application after it finishes."
            )
            event.ignore()
            return
        event.accept()

    def _load_integrity_history(self):
        if not hasattr(self, "integrity_history"):
            return
        evidence_id = self.hash_evidence_selector.currentData()
        checks = self.database.list_integrity_checks(limit=200)
        if evidence_id is not None:
            checks = [check for check in checks if check["evidence_id"] == evidence_id]
        self.integrity_history.setRowCount(0)
        for check in checks:
            row = self.integrity_history.rowCount()
            self.integrity_history.insertRow(row)
            values = [
                check["checked_at"].replace("T", " ")[:19],
                check["evidence_name"],
                check["status"],
                check["algorithms"],
            ]
            for column, value in enumerate(values):
                self.integrity_history.setItem(row, column, QTableWidgetItem(value))

    def _filesystem_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(10)

        controls = QHBoxLayout()
        self.filesystem_path = QLineEdit()
        self.filesystem_path.setPlaceholderText("Choose a directory to analyze...")
        choose = QPushButton("Choose directory")
        choose.clicked.connect(self._choose_filesystem_directory)
        self.filesystem_scan_button = QPushButton("Scan directory")
        self.filesystem_scan_button.clicked.connect(self._scan_filesystem)
        self.filesystem_cancel_button = QPushButton("Cancel scan")
        self.filesystem_cancel_button.clicked.connect(self._cancel_filesystem_scan)
        self.filesystem_cancel_button.setEnabled(False)
        controls.addWidget(self.filesystem_path, 1)
        controls.addWidget(choose)
        controls.addWidget(self.filesystem_scan_button)
        controls.addWidget(self.filesystem_cancel_button)
        layout.addLayout(controls)

        filters = QHBoxLayout()
        self.filesystem_filter = QLineEdit()
        self.filesystem_filter.setPlaceholderText(
            "Search names, paths, MIME types, and extensions..."
        )
        self.filesystem_filter.textChanged.connect(self._filter_filesystem_rows)
        self.hidden_only = QCheckBox("Hidden only")
        self.hidden_only.stateChanged.connect(self._filter_filesystem_rows)
        self.filesystem_kind = QComboBox()
        self.filesystem_kind.addItems(["All items", "Files only", "Folders only", "Links only"])
        self.filesystem_kind.currentTextChanged.connect(self._filter_filesystem_rows)
        self.filesystem_export_button = QPushButton("Export CSV")
        self.filesystem_export_button.clicked.connect(self._export_filesystem_csv)
        self.filesystem_export_button.setEnabled(False)
        filters.addWidget(self.filesystem_filter, 1)
        filters.addWidget(self.filesystem_kind)
        filters.addWidget(self.hidden_only)
        filters.addWidget(self.filesystem_export_button)
        layout.addLayout(filters)

        self.filesystem_status = QLabel("Choose a directory and scan it to begin analysis.")
        self.filesystem_status.setObjectName("statusLabel")
        layout.addWidget(self.filesystem_status)
        self.filesystem_progress = QProgressBar()
        self.filesystem_progress.setRange(0, 0)
        self.filesystem_progress.setTextVisible(False)
        self.filesystem_progress.hide()
        layout.addWidget(self.filesystem_progress)

        self.filesystem_table = QTableWidget(0, 11)
        self.filesystem_table.setHorizontalHeaderLabels(
            [
                "Name", "Type", "Extension", "Size (bytes)", "MIME type",
                "Modified", "Accessed", "Created", "Hidden", "System", "Path",
            ]
        )
        self.filesystem_table.setAlternatingRowColors(True)
        self.filesystem_table.setSortingEnabled(True)
        self.filesystem_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.filesystem_table.setSelectionMode(QTableWidget.SingleSelection)
        self.filesystem_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.filesystem_table.verticalHeader().setVisible(False)
        for column in range(10):
            self.filesystem_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeToContents
            )
        self.filesystem_table.horizontalHeader().setSectionResizeMode(10, QHeaderView.Stretch)
        self.filesystem_table.cellDoubleClicked.connect(self._inspect_filesystem_item)
        layout.addWidget(self.filesystem_table)
        self._filesystem_records = []
        return page

    def _choose_filesystem_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Choose directory to analyze")
        if directory:
            self.filesystem_path.setText(directory)
            self.filesystem_status.setText("Ready to scan: {}".format(directory))

    def _scan_filesystem(self):
        root_text = self.filesystem_path.text().strip()
        if not root_text:
            QMessageBox.information(
                self, "Choose a directory", "Select a directory before scanning."
            )
            return
        root = Path(root_text)
        if not root.is_dir():
            QMessageBox.warning(self, "Invalid directory", "The selected path is not a directory.")
            return
        if self.filesystem_thread is not None and self.filesystem_thread.isRunning():
            return
        self.filesystem_scan_button.setEnabled(False)
        self.filesystem_cancel_button.setEnabled(True)
        self.filesystem_export_button.setEnabled(False)
        self.filesystem_status.setText("Scanning {}...".format(root))
        self.filesystem_progress.show()
        self.filesystem_cancel = Event()
        self.filesystem_thread = QThread(self)
        self.filesystem_worker = FileSystemScanWorker(root, self.filesystem_cancel)
        self.filesystem_worker.moveToThread(self.filesystem_thread)
        self.filesystem_thread.started.connect(self.filesystem_worker.run)
        self.filesystem_worker.completed.connect(self._on_filesystem_scan_complete)
        self.filesystem_worker.failed.connect(self._on_filesystem_scan_failed)
        self.filesystem_worker.completed.connect(
            self.filesystem_thread.quit, Qt.DirectConnection
        )
        self.filesystem_worker.failed.connect(
            self.filesystem_thread.quit, Qt.DirectConnection
        )
        self.filesystem_thread.finished.connect(self.filesystem_worker.deleteLater)
        self.filesystem_thread.finished.connect(self._on_filesystem_thread_finished)
        self.filesystem_thread.start()

    def _on_filesystem_scan_complete(self, records, errors, cancelled):
        self._filesystem_records = records
        self.filesystem_table.setUpdatesEnabled(False)
        self.filesystem_table.setSortingEnabled(False)
        self.filesystem_table.setRowCount(len(records))
        for row, record in enumerate(records):
            values = [
                record["name"],
                record["type"],
                record["extension"],
                "" if record["size"] == "" else str(record["size"]),
                record["mime_type"],
                record["modified"],
                record["accessed"],
                record["created"],
                "Yes" if record["hidden"] else "No",
                "Yes" if record["system"] else "No",
                record["path"],
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (0, 10):
                    item.setToolTip(value)
                self.filesystem_table.setItem(row, column, item)
        self.filesystem_table.setSortingEnabled(True)
        self.filesystem_table.setUpdatesEnabled(True)
        self.filesystem_export_button.setEnabled(bool(records))
        self._filter_filesystem_rows()
        status = "Scan complete: {} item(s), {} access error(s).".format(
            len(records), len(errors)
        )
        if cancelled:
            status = "Scan cancelled: " + status
        self.filesystem_status.setText(status)
        if errors:
            QMessageBox.warning(
                self,
                "Some items could not be scanned",
                "{} item(s) were inaccessible. First error: {}".format(
                    len(errors), errors[0]
                ),
            )

    def _on_filesystem_scan_failed(self, message):
        self.filesystem_status.setText("Scan failed.")
        QMessageBox.critical(self, "File-system scan failed", message)

    def _cancel_filesystem_scan(self):
        if self.filesystem_cancel is not None:
            self.filesystem_cancel.set()
            self.filesystem_status.setText("Cancelling scan...")

    def _on_filesystem_thread_finished(self):
        self.filesystem_progress.hide()
        self.filesystem_scan_button.setEnabled(True)
        self.filesystem_cancel_button.setEnabled(False)
        self.filesystem_thread = None
        self.filesystem_worker = None
        self.filesystem_cancel = None

    def _filter_filesystem_rows(self, _state=None):
        if not hasattr(self, "filesystem_table"):
            return
        search = self.filesystem_filter.text().strip().lower()
        hidden_only = self.hidden_only.isChecked()
        selected_kind = self.filesystem_kind.currentText()
        kind_map = {
            "Files only": "File",
            "Folders only": "Directory",
            "Links only": "Symbolic link",
        }
        visible = 0
        for row in range(self.filesystem_table.rowCount()):
            searchable = " ".join(
                self.filesystem_table.item(row, column).text().lower()
                for column in (0, 2, 4, 10)
            )
            hidden = self.filesystem_table.item(row, 8).text() == "Yes"
            kind = self.filesystem_table.item(row, 1).text()
            matches = (
                (not search or search in searchable)
                and (not hidden_only or hidden)
                and (selected_kind == "All items" or kind == kind_map[selected_kind])
            )
            self.filesystem_table.setRowHidden(row, not matches)
            visible += int(matches)
        self.filesystem_status.setText(
            "{} of {} item(s) shown.".format(visible, self.filesystem_table.rowCount())
        )

    def _export_filesystem_csv(self):
        if not self._filesystem_records:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export file-system results", "filesystem_analysis.csv",
            "CSV files (*.csv)",
        )
        if not path:
            return
        headers = [
            "Name", "Type", "Extension", "Size (bytes)", "MIME type",
            "Modified", "Accessed", "Created", "Hidden", "System", "Path",
        ]
        rows = [
            [
                record["name"], record["type"], record["extension"], record["size"],
                record["mime_type"], record["modified"], record["accessed"],
                record["created"], record["hidden"], record["system"], record["path"],
            ]
            for record in self._filesystem_records
        ]
        try:
            export_rows_csv(path, headers, rows)
        except OSError as error:
            QMessageBox.critical(self, "Export failed", str(error))
            return
        self.statusBar().showMessage("File-system results exported.", 5000)

    def _inspect_filesystem_item(self, row, _column):
        path = self.filesystem_table.item(row, 10).text()
        if Path(path).is_file():
            evidence_id = next(
                (
                    item["id"] for item in self.database.list_all_evidence()
                    if Path(item["path"]).resolve().as_posix().casefold()
                    == Path(path).resolve().as_posix().casefold()
                ),
                None,
            )
            self.metadata_evidence_selector.setCurrentIndex(
                self.metadata_evidence_selector.findData(evidence_id)
                if evidence_id is not None else -1
            )
            self.metadata_path.setText(path)
            self.navigation.setCurrentRow(4)
            self._extract_metadata()

    def _metadata_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(10)
        controls = QHBoxLayout()
        self.metadata_evidence_selector = QComboBox()
        self.metadata_evidence_selector.setMinimumWidth(260)
        self.metadata_evidence_selector.currentIndexChanged.connect(
            self._metadata_evidence_changed
        )
        refresh = QPushButton("Refresh evidence")
        refresh.clicked.connect(self._load_metadata_evidence)
        controls.addWidget(QLabel("Registered evidence:"))
        controls.addWidget(self.metadata_evidence_selector, 1)
        controls.addWidget(refresh)
        layout.addLayout(controls)

        file_controls = QHBoxLayout()
        self.metadata_path = QLineEdit()
        self.metadata_path.setPlaceholderText("Choose registered evidence or analyze an external file...")
        choose = QPushButton("Browse file")
        choose.clicked.connect(self._choose_metadata_file)
        self.metadata_analyze_button = QPushButton("Analyze metadata")
        self.metadata_analyze_button.clicked.connect(self._extract_metadata)
        file_controls.addWidget(self.metadata_path, 1)
        file_controls.addWidget(choose)
        file_controls.addWidget(self.metadata_analyze_button)
        layout.addLayout(file_controls)

        self.metadata_status = QLabel(
            "Select registered evidence to inspect and save metadata findings, or browse an external file."
        )
        self.metadata_status.setObjectName("statusLabel")
        layout.addWidget(self.metadata_status)
        self.metadata_progress = QProgressBar()
        self.metadata_progress.setRange(0, 0)
        self.metadata_progress.setTextVisible(False)
        self.metadata_progress.hide()
        layout.addWidget(self.metadata_progress)

        results_layout = QHBoxLayout()
        self.metadata_table = QTableWidget(0, 2)
        self.metadata_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.metadata_table.setAlternatingRowColors(True)
        self.metadata_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.metadata_table.verticalHeader().setVisible(False)
        self.metadata_table.horizontalHeader().setStretchLastSection(True)
        self.metadata_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.metadata_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        results_layout.addWidget(self.metadata_table, 3)

        self.metadata_history = QTableWidget(0, 2)
        self.metadata_history.setHorizontalHeaderLabels(["Analyzed at", "Properties"])
        self.metadata_history.setAlternatingRowColors(True)
        self.metadata_history.setEditTriggers(QTableWidget.NoEditTriggers)
        self.metadata_history.verticalHeader().setVisible(False)
        self.metadata_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.metadata_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.metadata_history.itemSelectionChanged.connect(self._show_metadata_history_item)
        history_panel = QFrame()
        history_panel.setObjectName("panel")
        history_layout = QVBoxLayout(history_panel)
        history_layout.setContentsMargins(12, 12, 12, 12)
        history_heading = QLabel("Saved analyses")
        history_heading.setFont(QFont("Segoe UI", 12, QFont.Bold))
        history_layout.addWidget(history_heading)
        history_layout.addWidget(self.metadata_history)
        results_layout.addWidget(history_panel, 2)
        layout.addLayout(results_layout, 1)

        exports = QHBoxLayout()
        self.metadata_export_json_button = QPushButton("Export metadata JSON")
        self.metadata_export_json_button.clicked.connect(self._export_metadata)
        self.metadata_export_csv_button = QPushButton("Export metadata CSV")
        self.metadata_export_csv_button.clicked.connect(self._export_metadata_csv)
        self.metadata_export_json_button.setEnabled(False)
        self.metadata_export_csv_button.setEnabled(False)
        exports.addWidget(self.metadata_export_json_button)
        exports.addWidget(self.metadata_export_csv_button)
        exports.addStretch()
        layout.addLayout(exports)
        self._metadata = None
        self._load_metadata_evidence()
        return page

    def _load_metadata_evidence(self):
        if not hasattr(self, "metadata_evidence_selector"):
            return
        selected_id = self.metadata_evidence_selector.currentData()
        evidence_rows = self.database.list_all_evidence()
        self.metadata_evidence_selector.blockSignals(True)
        self.metadata_evidence_selector.clear()
        for evidence in evidence_rows:
            self.metadata_evidence_selector.addItem(
                "{} | {} | {}".format(
                    evidence["case_name"], evidence["name"], evidence["path"]
                ),
                evidence["id"],
            )
        index = (
            self.metadata_evidence_selector.findData(selected_id)
            if selected_id is not None else -1
        )
        if index < 0 and self.metadata_evidence_selector.count():
            index = 0
        self.metadata_evidence_selector.setCurrentIndex(index)
        self.metadata_evidence_selector.blockSignals(False)
        self._metadata_evidence_changed(index)

    def _metadata_evidence_changed(self, index):
        if index < 0:
            self.metadata_history.setRowCount(0)
            return
        evidence_id = self.metadata_evidence_selector.itemData(index)
        evidence = next(
            (item for item in self.database.list_all_evidence() if item["id"] == evidence_id),
            None,
        )
        if evidence is None:
            return
        self.metadata_path.setText(evidence["path"])
        self._load_metadata_history(evidence_id)

    def _load_metadata_history(self, evidence_id):
        records = self.database.list_metadata_findings(evidence_id)
        self.metadata_history.setRowCount(0)
        self.metadata_table.setRowCount(0)
        self._metadata = None
        self.metadata_export_json_button.setEnabled(False)
        self.metadata_export_csv_button.setEnabled(False)
        for record in records:
            try:
                metadata = json.loads(record["metadata_json"])
            except json.JSONDecodeError as error:
                self.metadata_status.setText(
                    "Saved metadata record is invalid: {}".format(error)
                )
                continue
            row = self.metadata_history.rowCount()
            self.metadata_history.insertRow(row)
            self.metadata_history.setItem(
                row, 0, QTableWidgetItem(record["extracted_at"].replace("T", " ")[:19])
            )
            count_item = QTableWidgetItem(str(len(metadata)))
            count_item.setData(Qt.UserRole, metadata)
            self.metadata_history.setItem(row, 1, count_item)
            self.metadata_history.item(row, 0).setData(Qt.UserRole, metadata)
        if records:
            self.metadata_history.selectRow(0)
        else:
            self._metadata = None
            self.metadata_table.setRowCount(0)
            self.metadata_status.setText("No saved metadata analysis exists for this evidence yet.")

    def _show_metadata_history_item(self):
        selected = self.metadata_history.selectedItems()
        if not selected:
            return
        metadata = selected[0].data(Qt.UserRole)
        if isinstance(metadata, dict):
            self._display_metadata(metadata)
            self.metadata_status.setText(
                "Showing saved analysis with {} properties.".format(len(metadata))
            )

    def _choose_metadata_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file for metadata analysis")
        if path:
            self.metadata_evidence_selector.blockSignals(True)
            self.metadata_evidence_selector.setCurrentIndex(-1)
            self.metadata_evidence_selector.blockSignals(False)
            self.metadata_history.setRowCount(0)
            self.metadata_table.setRowCount(0)
            self._metadata = None
            self.metadata_export_json_button.setEnabled(False)
            self.metadata_export_csv_button.setEnabled(False)
            self.metadata_path.setText(path)
            self.metadata_status.setText("Ready to inspect: {}".format(path))

    def _extract_metadata(self):
        path = self.metadata_path.text().strip()
        if not path:
            QMessageBox.information(self, "Choose a file", "Select a file before extracting metadata.")
            return
        evidence_id = self.metadata_evidence_selector.currentData()
        if self.metadata_thread is not None and self.metadata_thread.isRunning():
            return
        if not Path(path).is_file():
            QMessageBox.warning(self, "Invalid file", "The selected path is not a readable file.")
            return
        self.metadata_table.setRowCount(0)
        self._metadata = None
        self.metadata_export_json_button.setEnabled(False)
        self.metadata_export_csv_button.setEnabled(False)
        self.metadata_analyze_button.setEnabled(False)
        self.metadata_progress.show()
        self.metadata_status.setText("Extracting metadata. Large documents may take some time...")
        self.metadata_thread = QThread(self)
        self.metadata_worker = MetadataWorker(path, evidence_id)
        self.metadata_worker.moveToThread(self.metadata_thread)
        self.metadata_thread.started.connect(self.metadata_worker.run)
        self.metadata_worker.completed.connect(self._on_metadata_extracted)
        self.metadata_worker.failed.connect(self._on_metadata_extraction_failed)
        self.metadata_worker.completed.connect(self.metadata_thread.quit, Qt.DirectConnection)
        self.metadata_worker.failed.connect(self.metadata_thread.quit, Qt.DirectConnection)
        self.metadata_thread.finished.connect(self.metadata_worker.deleteLater)
        self.metadata_thread.finished.connect(self._on_metadata_thread_finished)
        self.metadata_thread.start()

    def _on_metadata_extracted(self, evidence_id, path, metadata):
        selected_id = self.metadata_evidence_selector.currentData()
        current_path = self.metadata_path.text().strip()
        is_current_request = (
            current_path
            and Path(current_path).resolve() == Path(path).resolve()
            and selected_id == evidence_id
        )
        if evidence_id is not None:
            evidence = next(
                (
                    item for item in self.database.list_all_evidence()
                    if item["id"] == evidence_id
                ),
                None,
            )
            if evidence is None:
                if is_current_request:
                    self.metadata_status.setText(
                        "The associated evidence record no longer exists; results were not saved."
                    )
                    self._display_metadata(metadata)
                else:
                    self.statusBar().showMessage(
                        "Metadata could not be saved because evidence record {} no longer exists.".format(
                            evidence_id
                        ),
                        5000,
                    )
                return
            metadata["Evidence ID"] = str(evidence_id)
            metadata["Registered SHA-256"] = evidence["sha256"]
            try:
                self.database.record_metadata_findings(
                    evidence_id, json.dumps(metadata, ensure_ascii=False)
                )
            except (OSError, ValueError, sqlite3.Error) as error:
                if is_current_request:
                    QMessageBox.critical(self, "Could not save metadata", str(error))
                return
            if is_current_request:
                self._load_metadata_history(evidence_id)
                self._display_metadata(metadata)
                self.metadata_status.setText(
                    "Metadata extracted and saved: {} properties.".format(len(metadata))
                )
            else:
                self.statusBar().showMessage(
                    "Metadata saved for evidence record {}.".format(evidence_id), 5000
                )
            self._refresh_dashboard()
        else:
            if is_current_request:
                self.metadata_status.setText(
                    "Metadata extracted for external file (not linked to a case): {} properties.".format(
                        len(metadata)
                    )
                )
                self._display_metadata(metadata)

    def _on_metadata_extraction_failed(self, evidence_id, path, message):
        if (
            self.metadata_path.text().strip()
            and Path(self.metadata_path.text()).resolve() == Path(path).resolve()
            and self.metadata_evidence_selector.currentData() == evidence_id
        ):
            self.metadata_status.setText("Metadata extraction failed.")
            QMessageBox.critical(self, "Metadata error", message)

    def _on_metadata_thread_finished(self):
        self.metadata_progress.hide()
        self.metadata_analyze_button.setEnabled(True)
        self.metadata_thread = None
        self.metadata_worker = None

    def _display_metadata(self, metadata):
        self.metadata_table.setRowCount(0)
        for key, value in metadata.items():
            row = self.metadata_table.rowCount()
            self.metadata_table.insertRow(row)
            self.metadata_table.setItem(row, 0, QTableWidgetItem(key))
            value_item = QTableWidgetItem(str(value))
            value_item.setToolTip(str(value))
            self.metadata_table.setItem(row, 1, value_item)
        self._metadata = dict(metadata)
        self.metadata_export_json_button.setEnabled(True)
        self.metadata_export_csv_button.setEnabled(True)

    def _export_metadata(self):
        if not self._metadata:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export metadata JSON", "", "JSON files (*.json)")
        if path:
            try:
                export_json(path, self._metadata)
            except OSError as error:
                QMessageBox.critical(self, "Metadata export failed", str(error))
                return
            self.metadata_status.setText("Metadata JSON exported to {}".format(path))

    def _export_metadata_csv(self):
        if not self._metadata:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export metadata CSV", "metadata.csv", "CSV files (*.csv)"
        )
        if path:
            try:
                export_rows_csv(
                    path,
                    ["Property", "Value"],
                    [[key, value] for key, value in self._metadata.items()],
                )
            except OSError as error:
                QMessageBox.critical(self, "Metadata export failed", str(error))
                return
            self.metadata_status.setText("Metadata CSV exported to {}".format(path))

    def _log_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)

        controls = QHBoxLayout()
        self.log_path = QLineEdit()
        self.log_path.setPlaceholderText("Choose a TXT, LOG, CSV, JSON, or JSONL log file...")
        self.log_path.setReadOnly(True)
        choose = QPushButton("Choose log")
        choose.clicked.connect(self._choose_log)
        self.log_analyze_button = QPushButton("Analyze")
        self.log_analyze_button.clicked.connect(self._analyze_log)
        controls.addWidget(self.log_path, 1)
        controls.addWidget(choose)
        controls.addWidget(self.log_analyze_button)
        layout.addLayout(controls)

        self.log_progress = QProgressBar()
        self.log_progress.setRange(0, 0)
        self.log_progress.setTextVisible(False)
        self.log_progress.hide()
        layout.addWidget(self.log_progress)

        history_heading = QLabel("Recent analyses")
        history_heading.setObjectName("pageSubtitle")
        layout.addWidget(history_heading)
        self.log_history = QTableWidget(0, 4)
        self.log_history.setHorizontalHeaderLabels(
            ["Analyzed", "Source", "Events", "Registered evidence"]
        )
        self.log_history.setMaximumHeight(150)
        self.log_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_history.setSelectionMode(QTableWidget.SingleSelection)
        self.log_history.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_history.horizontalHeader().setStretchLastSection(True)
        self.log_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.log_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.log_history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.log_history.itemSelectionChanged.connect(self._show_log_history_item)
        layout.addWidget(self.log_history)

        filters = QHBoxLayout()
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Search event messages...")
        self.log_search.textChanged.connect(self._filter_log_rows)
        self.log_severity = QComboBox()
        self.log_severity.addItems(["All severities"] + list(SEVERITIES))
        self.log_severity.currentTextChanged.connect(self._filter_log_rows)
        filters.addWidget(QLabel("Filter:"))
        filters.addWidget(self.log_search, 1)
        filters.addWidget(self.log_severity)
        layout.addLayout(filters)

        self.log_status = QLabel(
            "Choose a TXT, CSV, or JSON log file to begin analysis."
        )
        self.log_status.setObjectName("statusLabel")
        layout.addWidget(self.log_status)
        self.log_table = QTableWidget(0, 4)
        self.log_table.setHorizontalHeaderLabels(["Line", "Timestamp", "Severity", "Message"])
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSortingEnabled(True)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        for column in range(3):
            self.log_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeToContents
            )
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.log_table)
        self.log_export_button = QPushButton("Export events CSV")
        self.log_export_button.clicked.connect(self._export_log_events)
        self.log_export_button.setEnabled(False)
        layout.addWidget(self.log_export_button, 0, Qt.AlignLeft)
        self._load_log_history()
        return page

    def _choose_log(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose log file",
            "",
            "Log files (*.txt *.log *.csv *.json *.jsonl *.ndjson);;All files (*)",
        )
        if path:
            self.log_path.setText(path)
            self.log_history.clearSelection()
            self.log_table.setRowCount(0)
            self._log_events = []
            self.log_export_button.setEnabled(False)
            self.log_status.setText("Ready to analyze: {}".format(path))

    def _analyze_log(self):
        path = self.log_path.text().strip()
        if not path:
            QMessageBox.information(self, "Choose a log", "Select a log file before analyzing.")
            return
        if self.log_thread is not None and self.log_thread.isRunning():
            return
        normalized_path = os.path.normcase(os.path.abspath(path))
        evidence = next(
            (
                item for item in self.database.list_all_evidence()
                if os.path.normcase(os.path.abspath(item["path"])) == normalized_path
            ),
            None,
        )
        evidence_id = evidence["id"] if evidence is not None else None
        self.log_analyze_button.setEnabled(False)
        self.log_progress.show()
        self.log_status.setText("Analyzing log file...")
        self.log_thread = QThread(self)
        self.log_worker = LogAnalysisWorker(path, evidence_id)
        self.log_worker.moveToThread(self.log_thread)
        self.log_thread.started.connect(self.log_worker.run)
        self.log_worker.completed.connect(self._on_log_analyzed)
        self.log_worker.failed.connect(self._on_log_analysis_failed)
        self.log_worker.completed.connect(self.log_thread.quit, Qt.DirectConnection)
        self.log_worker.failed.connect(self.log_thread.quit, Qt.DirectConnection)
        self.log_thread.finished.connect(self.log_worker.deleteLater)
        self.log_thread.finished.connect(self._on_log_thread_finished)
        self.log_thread.start()

    def _on_log_analyzed(self, path, events, evidence_id):
        try:
            self.database.record_log_analysis(
                path, json.dumps(events, ensure_ascii=False), len(events), evidence_id
            )
        except (OSError, sqlite3.Error, ValueError) as error:
            save_error = error
        else:
            save_error = None
        self._load_log_history()
        is_current_request = (
            os.path.normcase(os.path.abspath(self.log_path.text().strip()))
            == os.path.normcase(os.path.abspath(path))
        )
        if not is_current_request:
            if save_error is not None:
                self.statusBar().showMessage(
                    "Log parsed, but the analysis could not be saved: {}".format(save_error),
                    7000,
                )
            else:
                self.statusBar().showMessage(
                    "Log analysis saved for {}.".format(Path(path).name), 5000
                )
            return
        self._log_events = events
        self.log_export_button.setEnabled(True)
        self._populate_log_table(events)
        counts = {}
        for event in events:
            counts[event["severity"]] = counts.get(event["severity"], 0) + 1
        summary = ", ".join(
            "{} {}".format(severity.title(), counts[severity])
            for severity in SEVERITIES
            if counts.get(severity)
        )
        status = "Analysis complete: {} events found. {}".format(len(events), summary)
        if save_error is not None:
            status += " Results could not be saved: {}".format(save_error)
            QMessageBox.critical(self, "Could not save log analysis", str(save_error))
        self.log_status.setText(status)

    def _on_log_analysis_failed(self, path, message):
        if (
            os.path.normcase(os.path.abspath(self.log_path.text().strip()))
            == os.path.normcase(os.path.abspath(path))
        ):
            self.log_status.setText("Log analysis failed.")
            QMessageBox.critical(self, "Log analysis error", message)

    def _on_log_thread_finished(self):
        self.log_progress.hide()
        self.log_analyze_button.setEnabled(True)
        self.log_thread = None
        self.log_worker = None

    def _load_log_history(self):
        self.log_history.blockSignals(True)
        self.log_history.setRowCount(0)
        invalid_source = None
        for record in self.database.list_log_analyses():
            try:
                events = json.loads(record["events_json"])
            except json.JSONDecodeError:
                invalid_source = record["source_path"]
                continue
            if not isinstance(events, list) or any(
                not isinstance(event, dict) for event in events
            ):
                invalid_source = record["source_path"]
                continue
            row = self.log_history.rowCount()
            self.log_history.insertRow(row)
            values = [
                record["analyzed_at"].replace("T", " ")[:19],
                record["source_path"],
                str(len(events)),
                record["evidence_name"] or "",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.UserRole, (record["source_path"], events))
                self.log_history.setItem(row, column, item)
        self.log_history.blockSignals(False)
        if invalid_source is not None:
            self.log_status.setText(
                "Saved log analysis contains invalid event data and was skipped: {}".format(
                    invalid_source
                )
            )

    def _show_log_history_item(self):
        selected = self.log_history.selectedItems()
        if not selected:
            return
        saved = self.log_history.item(selected[0].row(), 0).data(Qt.UserRole)
        if not isinstance(saved, tuple) or len(saved) != 2:
            return
        path, events = saved
        self.log_path.setText(path)
        self._log_events = events
        self.log_export_button.setEnabled(True)
        self._populate_log_table(events)
        self.log_status.setText(
            "Showing saved analysis: {} events from {}.".format(len(events), Path(path).name)
        )

    def _export_log_events(self):
        if not getattr(self, "_log_events", None):
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export log events CSV", "", "CSV files (*.csv)")
        if path:
            try:
                export_rows_csv(
                    path,
                    ["Line", "Timestamp", "Severity", "Message"],
                    [
                        [event["line"], event["timestamp"], event["severity"], event["message"]]
                        for event in self._log_events
                    ],
                )
            except OSError as error:
                QMessageBox.critical(self, "Log export failed", str(error))
            else:
                self.log_status.setText("Log events exported to {}".format(path))
            self.log_status.setText("Log events exported to {}".format(path))

    def _timeline_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        controls = QHBoxLayout()
        self.timeline_case_filter = QComboBox()
        self.timeline_case_filter.currentIndexChanged.connect(self._filter_timeline)
        self.timeline_type_filter = QComboBox()
        self.timeline_type_filter.currentIndexChanged.connect(self._filter_timeline)
        self.timeline_filter = QLineEdit()
        self.timeline_filter.setPlaceholderText("Filter timeline events...")
        self.timeline_filter.textChanged.connect(self._filter_timeline)
        controls.addWidget(QLabel("Case:"))
        controls.addWidget(self.timeline_case_filter)
        controls.addWidget(QLabel("Event:"))
        controls.addWidget(self.timeline_type_filter)
        layout.addLayout(controls)

        date_controls = QHBoxLayout()
        self.timeline_start_enabled = QCheckBox("From")
        self.timeline_start_enabled.toggled.connect(self._toggle_timeline_dates)
        self.timeline_start_date = QDateEdit()
        self.timeline_start_date.setCalendarPopup(True)
        self.timeline_start_date.setDisplayFormat("yyyy-MM-dd")
        self.timeline_start_date.setKeyboardTracking(False)
        self.timeline_start_date.setMinimumWidth(125)
        self.timeline_start_date.dateChanged.connect(self._filter_timeline)
        self.timeline_end_enabled = QCheckBox("To")
        self.timeline_end_enabled.toggled.connect(self._toggle_timeline_dates)
        self.timeline_end_date = QDateEdit()
        self.timeline_end_date.setCalendarPopup(True)
        self.timeline_end_date.setDisplayFormat("yyyy-MM-dd")
        self.timeline_end_date.setKeyboardTracking(False)
        self.timeline_end_date.setMinimumWidth(125)
        self.timeline_end_date.dateChanged.connect(self._filter_timeline)
        date_controls.addWidget(self.timeline_start_enabled)
        date_controls.addWidget(self.timeline_start_date)
        date_controls.addWidget(self.timeline_end_enabled)
        date_controls.addWidget(self.timeline_end_date)
        date_controls.addWidget(self.timeline_filter, 1)
        refresh = QPushButton("Refresh timeline")
        refresh.clicked.connect(self._load_timeline)
        date_controls.addWidget(refresh)
        self.timeline_export_button = QPushButton("Export CSV")
        self.timeline_export_button.clicked.connect(self._export_timeline)
        date_controls.addWidget(self.timeline_export_button)
        layout.addLayout(date_controls)
        self.timeline_status = QLabel()
        self.timeline_status.setObjectName("statusLabel")
        layout.addWidget(self.timeline_status)
        self.timeline_table = QTableWidget(0, 5)
        self.timeline_table.setHorizontalHeaderLabels(
            ["Timestamp", "Event type", "Subject", "Details", "Case"]
        )
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.setSortingEnabled(True)
        for column in (0, 1, 2, 4):
            self.timeline_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeToContents
            )
        self.timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.timeline_table)
        self._load_timeline()
        return page

    def _toggle_timeline_dates(self, _enabled):
        self._filter_timeline()

    def _load_timeline(self):
        selected_case = self.timeline_case_filter.currentData()
        selected_type = self.timeline_type_filter.currentData()
        cases = self.database.list_cases()
        self.timeline_case_filter.blockSignals(True)
        self.timeline_case_filter.clear()
        self.timeline_case_filter.addItem("All cases", None)
        for case in cases:
            self.timeline_case_filter.addItem(case["name"], case["id"])
        case_index = self.timeline_case_filter.findData(selected_case)
        self.timeline_case_filter.setCurrentIndex(max(case_index, 0))
        self.timeline_case_filter.blockSignals(False)

        events = sort_events(self.database.list_timeline())
        self._timeline_events = [dict(event) for event in events]
        self.timeline_type_filter.blockSignals(True)
        self.timeline_type_filter.clear()
        self.timeline_type_filter.addItem("All event types", "All event types")
        event_types = sorted({event["event_type"] for event in self._timeline_events})
        for event_type in event_types:
            self.timeline_type_filter.addItem(event_type, event_type)
        type_index = self.timeline_type_filter.findData(selected_type)
        self.timeline_type_filter.setCurrentIndex(max(type_index, 0))
        self.timeline_type_filter.blockSignals(False)
        self._filter_timeline()

    def _filter_timeline(self, _value=None):
        if not hasattr(self, "timeline_table"):
            return
        case_id = self.timeline_case_filter.currentData()
        event_type = self.timeline_type_filter.currentData()
        start_date = (
            self.timeline_start_date.date().toPyDate()
            if self.timeline_start_enabled.isChecked() else None
        )
        end_date = (
            self.timeline_end_date.date().toPyDate()
            if self.timeline_end_enabled.isChecked() else None
        )
        if start_date is not None and end_date is not None and start_date > end_date:
            self.timeline_status.setText("The start date must be on or before the end date.")
            self.timeline_table.setRowCount(0)
            self._visible_timeline_events = []
            return
        events = filter_events(
            self._timeline_events,
            query=self.timeline_filter.text(),
            event_type=event_type or "All event types",
            case_id=case_id,
            start_date=start_date,
            end_date=end_date,
        )
        self._visible_timeline_events = events
        self.timeline_table.setSortingEnabled(False)
        self.timeline_table.setRowCount(0)
        for event in events:
            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)
            for column, key in enumerate(
                ("timestamp", "event_type", "subject", "details", "case_name")
            ):
                self.timeline_table.setItem(row, column, QTableWidgetItem(str(event[key] or "")))
        self.timeline_table.setSortingEnabled(True)
        self.timeline_status.setText(
            "{} timeline event(s) shown ({} total)".format(
                len(events), len(self._timeline_events)
            )
        )

    def _export_timeline(self):
        events = getattr(self, "_visible_timeline_events", [])
        if not events:
            QMessageBox.information(
                self, "No timeline events", "There are no visible timeline events to export."
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export timeline CSV", "", "CSV files (*.csv)"
        )
        if not path:
            return
        try:
            export_rows_csv(
                path,
                ["Timestamp", "Event type", "Subject", "Details", "Case"],
                [
                    [
                        event.get("timestamp", ""),
                        event.get("event_type", ""),
                        event.get("subject", ""),
                        event.get("details", ""),
                        event.get("case_name", ""),
                    ]
                    for event in events
                ],
            )
        except OSError as error:
            QMessageBox.critical(self, "Timeline export failed", str(error))
        else:
            self.timeline_status.setText(
                "{} filtered timeline event(s) exported to {}".format(len(events), path)
            )

    def _search_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        controls = QHBoxLayout()
        self.global_search_input = QLineEdit()
        self.global_search_input.setPlaceholderText(
            "Search cases, evidence, hashes, custody, metadata, logs, reports, and activity (use * for all)..."
        )
        self.global_search_input.returnPressed.connect(self._run_global_search)
        self.global_search_type = QComboBox()
        self.global_search_type.addItems(
            [
                "All result types",
                "Case",
                "Evidence",
                "Chain of custody",
                "Integrity check",
                "Metadata analysis",
                "Log analysis",
                "Log event",
                "Report",
                "Activity",
            ]
        )
        self.global_search_case = QComboBox()
        self.global_search_case.addItem("All cases", None)
        for case in self.database.list_cases():
            self.global_search_case.addItem(case["name"], case["id"])
        search = QPushButton("Search")
        search.clicked.connect(self._run_global_search)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear_global_search)
        controls.addWidget(self.global_search_input, 1)
        controls.addWidget(self.global_search_type)
        controls.addWidget(self.global_search_case)
        controls.addWidget(search)
        controls.addWidget(clear)
        layout.addLayout(controls)
        self.global_search_status = QLabel("Enter a search term to search the investigation database.")
        self.global_search_status.setObjectName("statusLabel")
        layout.addWidget(self.global_search_status)
        self.global_search_table = QTableWidget(0, 5)
        self.global_search_table.setHorizontalHeaderLabels(
            ["Type", "Title", "Details", "Timestamp", "Case"]
        )
        self.global_search_table.setAlternatingRowColors(True)
        self.global_search_table.setSortingEnabled(True)
        self.global_search_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.global_search_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.global_search_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.global_search_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.global_search_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        layout.addWidget(self.global_search_table)
        self.global_search_export_button = QPushButton("Export results CSV")
        self.global_search_export_button.setEnabled(False)
        self.global_search_export_button.clicked.connect(self._export_global_search)
        layout.addWidget(self.global_search_export_button, 0, Qt.AlignLeft)
        return page

    def _run_global_search(self):
        query = self.global_search_input.text().strip()
        self.global_search_table.setRowCount(0)
        self._global_search_results = []
        self.global_search_export_button.setEnabled(False)
        if not query:
            self.global_search_status.setText("Enter a search term to search the investigation database.")
            return
        try:
            results = self.database.search(
                query,
                result_type=self.global_search_type.currentText(),
                case_id=self.global_search_case.currentData(),
            )
        except sqlite3.Error as error:
            self.global_search_status.setText("Search failed.")
            QMessageBox.critical(self, "Search error", str(error))
            return
        self._global_search_results = [dict(result) for result in results]
        self.global_search_table.setSortingEnabled(False)
        for result in self._global_search_results:
            row = self.global_search_table.rowCount()
            self.global_search_table.insertRow(row)
            for column, key in enumerate(
                ("result_type", "title", "details", "timestamp", "case_name")
            ):
                self.global_search_table.setItem(
                    row, column, QTableWidgetItem(str(result.get(key) or ""))
                )
        self.global_search_table.setSortingEnabled(True)
        self.global_search_export_button.setEnabled(bool(results))
        message = "{} result(s) found for '{}'".format(len(results), query)
        if len(results) == 500:
            message += " (showing the first 500; refine your search to narrow results)"
        self.global_search_status.setText(message)

    def _clear_global_search(self):
        self.global_search_input.clear()
        self.global_search_type.setCurrentIndex(0)
        self.global_search_case.setCurrentIndex(0)
        self.global_search_table.setRowCount(0)
        self._global_search_results = []
        self.global_search_export_button.setEnabled(False)
        self.global_search_status.setText(
            "Enter a search term to search the investigation database."
        )

    def _export_global_search(self):
        results = getattr(self, "_global_search_results", [])
        if not results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export search results", "", "CSV files (*.csv)"
        )
        if not path:
            return
        try:
            export_rows_csv(
                path,
                ["Type", "Title", "Details", "Timestamp", "Case"],
                [
                    [
                        result.get("result_type", ""),
                        result.get("title", ""),
                        result.get("details", ""),
                        result.get("timestamp", ""),
                        result.get("case_name", ""),
                    ]
                    for result in results
                ],
            )
        except OSError as error:
            QMessageBox.critical(self, "Search export failed", str(error))
        else:
            self.global_search_status.setText(
                "{} search result(s) exported to {}".format(len(results), path)
            )

    def _populate_log_table(self, events):
        self.log_table.setSortingEnabled(False)
        self.log_table.setRowCount(0)
        for event in events:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            values = [event["line"], event["timestamp"], event["severity"], event["message"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 2:
                    if value == "CRITICAL":
                        item.setForeground(Qt.red)
                    elif value == "ERROR":
                        item.setForeground(Qt.darkRed)
                    elif value == "WARNING":
                        item.setForeground(Qt.darkYellow)
                self.log_table.setItem(row, column, item)
        self.log_table.setSortingEnabled(True)
        self._filter_log_rows()

    def _filter_log_rows(self, _value=None):
        if not hasattr(self, "log_table"):
            return
        search = self.log_search.text().strip().lower()
        severity = self.log_severity.currentText()
        for row in range(self.log_table.rowCount()):
            message = self.log_table.item(row, 3).text().lower()
            row_severity = self.log_table.item(row, 2).text()
            visible = (not search or search in message) and (
                severity == "All severities" or row_severity == severity
            )
            self.log_table.setRowHidden(row, not visible)

    def _module_page(self, title):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(28, 28, 28, 28)
        heading = QLabel("{} workspace".format(title))
        heading.setFont(QFont("Segoe UI", 16, QFont.Bold))
        description = QLabel(
            "This module is ready for implementation. Its controls and data views "
            "will be connected to the investigation database here."
        )
        description.setWordWrap(True)
        description.setObjectName("muted")
        action = QPushButton("Start with {} ".format(title))
        action.setEnabled(False)
        action.setObjectName("disabledAction")
        panel_layout.addWidget(heading)
        panel_layout.addWidget(description)
        panel_layout.addSpacing(12)
        panel_layout.addWidget(action, 0, Qt.AlignLeft)
        panel_layout.addStretch()
        layout.addWidget(panel)
        layout.addStretch()
        return page

    @staticmethod
    def _stat_card(label, value, color):
        card = QFrame()
        card.setObjectName("statCard")
        card.setMinimumHeight(120)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        marker = QLabel("●  {}".format(label))
        marker.setStyleSheet("color: {};".format(color))
        number = QLabel(value)
        number.setFont(QFont("Segoe UI", 28, QFont.Bold))
        layout.addWidget(marker)
        layout.addWidget(number)
        return card

    @staticmethod
    def _panel(title, message):
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 18, 20, 18)
        heading = QLabel(title)
        heading.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(heading)
        if message:
            text = QLabel(message)
            text.setWordWrap(True)
            text.setObjectName("muted")
            layout.addWidget(text)
        layout.addStretch()
        return panel
