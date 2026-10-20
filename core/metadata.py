"""File metadata extraction — MAC timestamps, attributes, ownership."""

import os
import datetime
from pathlib import Path
from dataclasses import dataclass

try:
    import win32security
    import win32api
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

FILE_ATTRIBUTE_READONLY  = 0x0001
FILE_ATTRIBUTE_HIDDEN    = 0x0002
FILE_ATTRIBUTE_SYSTEM    = 0x0004
FILE_ATTRIBUTE_ARCHIVE   = 0x0020


@dataclass
class FileMetadata:
    path: str
    name: str
    size: int
    created: datetime.datetime
    modified: datetime.datetime
    accessed: datetime.datetime
    is_hidden: bool
    is_system: bool
    is_readonly: bool
    is_archive: bool
    owner: str
    extension: str
    attributes: int


def _get_owner(path: str) -> str:
    if not HAS_WIN32:
        return "N/A (Windows only)"
    try:
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}"
    except Exception:
        return "Unknown"


def _get_attributes(path: str) -> int:
    if not HAS_WIN32:
        return FILE_ATTRIBUTE_HIDDEN if Path(path).name.startswith('.') else 0
    try:
        return win32api.GetFileAttributes(path)
    except Exception:
        return 0


def extract_metadata(path: str) -> FileMetadata:
    p = Path(path)
    st = p.stat()
    attrs = _get_attributes(path)

    return FileMetadata(
        path=str(p.resolve()),
        name=p.name,
        size=st.st_size,
        # Windows: st_ctime = file creation time (correct for forensics)
        # Linux/macOS: st_ctime = inode-change time (NOT creation time - document this)
        created=datetime.datetime.fromtimestamp(st.st_ctime),
        modified=datetime.datetime.fromtimestamp(st.st_mtime),
        accessed=datetime.datetime.fromtimestamp(st.st_atime),
        is_hidden=bool(attrs & FILE_ATTRIBUTE_HIDDEN),
        is_system=bool(attrs & FILE_ATTRIBUTE_SYSTEM),
        is_readonly=bool(attrs & FILE_ATTRIBUTE_READONLY),
        is_archive=bool(attrs & FILE_ATTRIBUTE_ARCHIVE),
        owner=_get_owner(path),
        extension=p.suffix.lower(),
        attributes=attrs,
    )


def scan_directory(directory: str, recursive: bool = True, progress_cb=None):
    """Scan directory and return list of FileMetadata. Read-only, never modifies files."""
    target = Path(directory)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {directory}")

    results = []
    walker = target.rglob('*') if recursive else target.iterdir()

    for item in walker:
        if item.is_file() and not item.is_symlink():
            try:
                meta = extract_metadata(str(item))
                results.append(meta)
                if progress_cb:
                    progress_cb(meta)
            except (PermissionError, OSError):
                pass

    return results
