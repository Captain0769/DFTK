import mimetypes
import os
import stat
from datetime import datetime
from pathlib import Path


def scan_directory(root, cancel_event=None):
    """Walk a directory without following symbolic links and collect file metadata."""
    root_path = Path(root)
    if not root_path.is_dir():
        raise NotADirectoryError(str(root_path))

    records = []
    errors = []

    def on_walk_error(error):
        errors.append("{}: {}".format(getattr(error, "filename", root_path), error))

    for current_root, directories, files in os.walk(
        str(root_path), topdown=True, followlinks=False, onerror=on_walk_error
    ):
        if cancel_event is not None and cancel_event.is_set():
            break
        current_path = Path(current_root)
        for name in directories + files:
            if cancel_event is not None and cancel_event.is_set():
                break
            path = current_path / name
            try:
                file_stat = path.stat(follow_symlinks=False)
            except OSError as error:
                errors.append("{}: {}".format(path, error))
                continue

            is_directory = stat.S_ISDIR(file_stat.st_mode)
            is_symlink = stat.S_ISLNK(file_stat.st_mode)
            attributes = getattr(file_stat, "st_file_attributes", 0)
            extension = path.suffix.lower()
            records.append(
                {
                    "name": path.name,
                    "type": "Symbolic link" if is_symlink else (
                        "Directory" if is_directory else "File"
                    ),
                    "extension": extension or ("(none)" if not is_directory else ""),
                    "mime_type": (
                        "" if is_directory
                        else mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                    ),
                    "size": "" if is_directory else file_stat.st_size,
                    "modified": _timestamp(file_stat.st_mtime),
                    "accessed": _timestamp(file_stat.st_atime),
                    "created": _timestamp(_creation_time(file_stat)),
                    "hidden": path.name.startswith(".") or bool(attributes & 0x2),
                    "system": bool(attributes & 0x4),
                    "path": str(path),
                }
            )

    records.sort(key=lambda record: record["path"].casefold())
    return records, errors


def _creation_time(file_stat):
    if hasattr(file_stat, "st_birthtime"):
        return file_stat.st_birthtime
    return file_stat.st_ctime


def _timestamp(value):
    return datetime.fromtimestamp(value).isoformat(sep=" ", timespec="seconds")
