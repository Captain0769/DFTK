import csv
import json
from pathlib import Path


def export_rows_csv(path, headers, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)


def export_json(path, payload):
    with Path(path).open("w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2, default=str)


def export_pdf(path, title, sections):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    document = canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 50
    document.setTitle(title)
    document.setFont("Helvetica-Bold", 16)
    document.drawString(45, y, title)
    y -= 30
    document.setFont("Helvetica", 9)
    for heading, lines in sections:
        if y < 60:
            document.showPage()
            y = height - 50
        document.setFont("Helvetica-Bold", 11)
        document.drawString(45, y, heading)
        y -= 16
        document.setFont("Helvetica", 9)
        for line in lines:
            for wrapped in _wrap(str(line), 110):
                if y < 45:
                    document.showPage()
                    y = height - 50
                document.drawString(55, y, wrapped)
                y -= 13
        y -= 10
    document.save()


def _wrap(text, width):
    return [text[index:index + width] for index in range(0, len(text), width)] or [""]
