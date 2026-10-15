import mimetypes
import stat
import zipfile
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree


def extract_metadata(path):
    """Extract safe, offline metadata without modifying the source file."""
    file_path = Path(path)
    file_stat = file_path.stat()
    created_time = getattr(file_stat, "st_birthtime", None)
    metadata = {
        "Name": file_path.name,
        "Path": str(file_path),
        "Size (bytes)": str(file_stat.st_size),
        "Extension": file_path.suffix.lower() or "(none)",
        "MIME type": mimetypes.guess_type(file_path.name)[0] or "application/octet-stream",
        "Created": _timestamp(created_time) if created_time is not None else "Unavailable on this platform",
        "Modified": _timestamp(file_stat.st_mtime),
        "Accessed": _timestamp(file_stat.st_atime),
        "Permissions": stat.filemode(file_stat.st_mode),
        "Hidden": "Yes" if _is_hidden(file_path) else "No",
        "Read-only": "Yes" if not file_stat.st_mode & stat.S_IWRITE else "No",
    }
    attributes = getattr(file_stat, "st_file_attributes", 0)
    metadata["System"] = "Yes" if attributes & 0x4 else "No"
    metadata.update(_format_specific_metadata(file_path))
    return metadata


def _format_specific_metadata(path):
    if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".tiff", ".webp", ".bmp", ".gif"}:
        return _image_metadata(path)
    if path.suffix.lower() == ".pdf":
        return _pdf_metadata(path)
    if path.suffix.lower() in {
        ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"
    }:
        return _office_metadata(path)
    return {}


def _image_metadata(path):
    try:
        from PIL import Image

        with Image.open(path) as image:
            result = {
                "Image format": image.format or "",
                "Image dimensions": "{} x {}".format(*image.size),
            }
            exif = image.getexif()
            for key, value in exif.items():
                name = _exif_name(key)
                result["EXIF: " + name] = str(value)
            return result
    except ImportError:
        return {"Image metadata": "Install Pillow to extract EXIF data"}
    except (OSError, ValueError):
        return {"Image metadata": "Unable to read image metadata"}


def _pdf_metadata(path):
    try:
        from pypdf import PdfReader
        from pypdf.errors import FileNotDecryptedError, PdfReadError

        reader = PdfReader(str(path), strict=False)
        result = {"PDF encrypted": "Yes" if reader.is_encrypted else "No"}
        if not reader.is_encrypted:
            result["PDF pages"] = str(len(reader.pages))
        if reader.metadata:
            for key, value in reader.metadata.items():
                normalized_key = str(key).lstrip("/")
                if value is not None:
                    result["PDF: " + normalized_key] = str(value)
        return result
    except ImportError:
        return {"PDF metadata": "Install pypdf to extract document properties"}
    except (OSError, ValueError, KeyError, PdfReadError, FileNotDecryptedError):
        return {"PDF metadata": "Unable to read PDF metadata"}


def _office_metadata(path):
    try:
        with zipfile.ZipFile(path) as archive:
            xml_data = archive.read("docProps/core.xml")
            try:
                app_data = archive.read("docProps/app.xml")
            except KeyError:
                app_data = None
        root = ElementTree.fromstring(xml_data)
        namespaces = {
            "dc": "http://purl.org/dc/elements/1.1/",
            "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
            "dcterms": "http://purl.org/dc/terms/",
        }
        fields = {
            "Office title": "dc:title",
            "Office subject": "dc:subject",
            "Office creator": "dc:creator",
            "Office keywords": "cp:keywords",
            "Office created": "dcterms:created",
            "Office modified": "dcterms:modified",
            "Office last modified by": "cp:lastModifiedBy",
            "Office revision": "cp:revision",
        }
        result = {}
        for label, expression in fields.items():
            element = root.find(expression, namespaces)
            if element is not None and element.text:
                result[label] = element.text
        if app_data is not None:
            app_root = ElementTree.fromstring(app_data)
            app_namespace = {
                "app": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            }
            for label, expression in (
                ("Office application", "app:Application"),
                ("Office company", "app:Company"),
                ("Office pages", "app:Pages"),
                ("Office words", "app:Words"),
            ):
                element = app_root.find(expression, app_namespace)
                if element is not None and element.text:
                    result[label] = element.text
        return result or {"Office metadata": "No core document properties found"}
    except (KeyError, OSError, zipfile.BadZipFile, ElementTree.ParseError):
        return {"Office metadata": "Unable to read document properties"}


def _exif_name(tag):
    try:
        from PIL.ExifTags import TAGS

        return TAGS.get(tag, str(tag))
    except ImportError:
        return str(tag)


def _timestamp(value):
    return datetime.fromtimestamp(value).isoformat(sep=" ", timespec="seconds")


def _is_hidden(path):
    if path.name.startswith("."):
        return True
    try:
        import ctypes

        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attributes != -1 and bool(attributes & 0x2)
    except (AttributeError, OSError):
        return False
