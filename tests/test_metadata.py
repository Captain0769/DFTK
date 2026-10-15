import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.database import Database
from core.metadata import extract_metadata


class MetadataAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_extracts_common_filesystem_properties(self):
        source = self.root / "notes.txt"
        source.write_text("case notes", encoding="utf-8")
        metadata = extract_metadata(source)

        self.assertEqual(metadata["Name"], "notes.txt")
        self.assertEqual(metadata["Size (bytes)"], "10")
        self.assertEqual(metadata["Extension"], ".txt")
        self.assertEqual(metadata["MIME type"], "text/plain")
        self.assertTrue(metadata["Created"])
        self.assertTrue(metadata["Modified"])
        self.assertTrue(metadata["Permissions"])
        self.assertEqual(metadata["Read-only"], "No")

    def test_extracts_image_and_pdf_properties(self):
        from PIL import Image
        from reportlab.pdfgen import canvas

        image_path = self.root / "pixel.png"
        Image.new("RGB", (3, 2), color="red").save(image_path)
        image_metadata = extract_metadata(image_path)
        self.assertEqual(image_metadata["Image format"], "PNG")
        self.assertEqual(image_metadata["Image dimensions"], "3 x 2")

        pdf_path = self.root / "report.pdf"
        pdf = canvas.Canvas(str(pdf_path))
        pdf.setTitle("DFTK metadata test")
        pdf.setAuthor("PBL analyst")
        pdf.drawString(40, 800, "test")
        pdf.save()
        pdf_metadata = extract_metadata(pdf_path)
        self.assertEqual(pdf_metadata["PDF pages"], "1")
        self.assertEqual(pdf_metadata["PDF: Title"], "DFTK metadata test")
        self.assertEqual(pdf_metadata["PDF: Author"], "PBL analyst")

    def test_extracts_office_core_and_extended_properties(self):
        office_path = self.root / "document.docm"
        core_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
          xmlns:dc="http://purl.org/dc/elements/1.1/">
          <dc:title>Incident notes</dc:title><dc:creator>Analyst A</dc:creator>
        </cp:coreProperties>"""
        app_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
          <Application>Word</Application><Company>DFTK Lab</Company>
        </Properties>"""
        with zipfile.ZipFile(office_path, "w") as archive:
            archive.writestr("docProps/core.xml", core_xml)
            archive.writestr("docProps/app.xml", app_xml)
        metadata = extract_metadata(office_path)
        self.assertEqual(metadata["Office title"], "Incident notes")
        self.assertEqual(metadata["Office creator"], "Analyst A")
        self.assertEqual(metadata["Office application"], "Word")
        self.assertEqual(metadata["Office company"], "DFTK Lab")

    def test_metadata_findings_are_saved_with_evidence(self):
        database = Database(self.root / "metadata.db")
        case_id = database.create_case("Metadata case")
        source = self.root / "evidence.txt"
        source.write_text("evidence", encoding="utf-8")
        evidence_id = database.add_evidence(
            case_id, source.name, str(source), "File", source.stat().st_size, {}
        )
        metadata = extract_metadata(source)
        encoded = json.dumps(metadata)
        database.record_metadata_findings(evidence_id, encoded)

        findings = database.list_metadata_findings(evidence_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(json.loads(findings[0]["metadata_json"])["Name"], "evidence.txt")
        self.assertTrue(findings[0]["extracted_at"])
        activity = database.list_activity(limit=10)
        self.assertTrue(any(row["action"] == "Metadata analyzed" for row in activity))


if __name__ == "__main__":
    unittest.main()
