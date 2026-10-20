"""Cryptographic hashing engine — MD5, SHA-1, SHA-256 with duplicate detection."""

import hashlib
import logging
import re
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Optional

CHUNK = 1 << 16  # 64 KB

log = logging.getLogger(__name__)


@dataclass
class FileHashes:
    path: str
    md5: str
    sha1: str
    sha256: str
    size: int


def compute_hashes(path: str, progress_cb: Optional[Callable[[int], None]] = None) -> FileHashes:
    """Compute MD5/SHA-1/SHA-256 in a single pass. Read-only."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    size   = 0

    with open(path, 'rb') as f:
        while chunk := f.read(CHUNK):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
            if progress_cb:
                progress_cb(size)

    return FileHashes(
        path=path,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size=size,
    )


def hash_all(paths: list[str], progress_cb=None) -> list[FileHashes]:
    results = []
    for path in paths:
        try:
            fh = compute_hashes(path)
            results.append(fh)
        except OSError as exc:  # PermissionError is a subclass of OSError
            log.warning("Skipped unreadable file %s: %s", path, exc)
        if progress_cb:
            progress_cb(path)
    return results


def find_duplicates(hashes: list[FileHashes]) -> dict[str, list[str]]:
    """Return dict mapping SHA-256 -> [paths] for files that share a hash.

    SHA-256 is used (not MD5) because MD5 collisions can be constructed on
    purpose, so two different files could otherwise be reported as copies.
    """
    groups: dict[str, list[str]] = {}
    for fh in hashes:
        groups.setdefault(fh.sha256, []).append(fh.path)
    return {h: paths for h, paths in groups.items() if len(paths) > 1}


# ── Hash sets: NSRL (known-good) and known-bad lists ─────────────────────────

KNOWN_GOOD = 'known-good'
KNOWN_BAD = 'known-bad'

# Hex digest lengths: MD5 = 32, SHA-1 = 40, SHA-256 = 64 hex characters.
_HASH_RE = re.compile(r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])')
_SQLITE_MAGIC = b'SQLite format 3\x00'


class HashDatabase:
    """A set of hashes plus what a match means.

    kind is KNOWN_GOOD for the NSRL (a match means "ignore this file", it is a
    standard OS/application file) or KNOWN_BAD for a malware list (a match
    means "investigate"). Text/CSV files are loaded into memory. A modern NSRL
    RDS SQLite file is NOT loaded (it holds hundreds of millions of rows); it
    is queried one hash at a time instead.
    """

    def __init__(self, name: str, kind: str, hashes: Optional[set] = None,
                 sqlite_path: Optional[str] = None):
        self.name = name
        self.kind = kind
        self._hashes: set[str] = hashes or set()
        self._conn = None
        self._cols: list[str] = []
        if sqlite_path:
            self._conn = sqlite3.connect(f'file:{sqlite_path}?mode=ro', uri=True)
            cols = [r[1].lower() for r in self._conn.execute('PRAGMA table_info(FILE)')]
            self._cols = [c for c in ('sha256', 'sha1', 'md5') if c in cols]
            if not self._cols:
                raise ValueError('SQLite file has no FILE table with sha256/sha1/md5 columns')

    def close(self) -> None:
        """Release an open read-only SQLite reference database."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __len__(self) -> int:
        if self._conn is not None:
            return self._conn.execute('SELECT COUNT(*) FROM FILE').fetchone()[0]
        return len(self._hashes)

    def __bool__(self) -> bool:
        return self._conn is not None or bool(self._hashes)

    def contains(self, digest: str, algo: str) -> bool:
        digest = digest.lower()
        if self._conn is None:
            return digest in self._hashes
        if algo not in self._cols:
            return False
        row = self._conn.execute(
            f'SELECT 1 FROM FILE WHERE lower({algo}) = ? LIMIT 1', (digest,)).fetchone()
        return row is not None

    def matches(self, fh: 'FileHashes') -> bool:
        return (self.contains(fh.sha256, 'sha256') or
                self.contains(fh.sha1, 'sha1') or
                self.contains(fh.md5, 'md5'))


def load_hashset(filepath: str) -> set[str]:
    """Load every MD5 / SHA-1 / SHA-256 found in a text or CSV file.

    Works for a plain one-hash-per-line list and for the classic NSRL
    NSRLFile.txt CSV ("SHA-1","MD5","CRC32","FileName",...), because it picks
    out the hex strings by length rather than by column position.
    """
    result: set[str] = set()
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            for m in _HASH_RE.findall(line):
                result.add(m.lower())
    return result


def load_hash_database(filepath: str, kind: Optional[str] = None) -> HashDatabase:
    """Load a hash set and decide what a match means.

    kind=None guesses: a file called *nsrl* or an SQLite RDS is known-good,
    anything else is treated as a known-bad list.
    """
    name = Path(filepath).name
    with open(filepath, 'rb') as f:
        is_sqlite = f.read(16) == _SQLITE_MAGIC
    if kind is None:
        kind = KNOWN_GOOD if (is_sqlite or 'nsrl' in name.lower()) else KNOWN_BAD
    if is_sqlite:
        return HashDatabase(name, kind, sqlite_path=filepath)
    return HashDatabase(name, kind, hashes=load_hashset(filepath))


def match_against_hashset(hashes: list[FileHashes], hashset) -> list[FileHashes]:
    """Return entries whose MD5, SHA-1 OR SHA-256 appears in the hash set.

    hashset may be a plain set of lowercase hex strings or a HashDatabase.
    """
    if isinstance(hashset, HashDatabase):
        return [fh for fh in hashes if hashset.matches(fh)]
    return [fh for fh in hashes
            if fh.md5 in hashset or fh.sha1 in hashset or fh.sha256 in hashset]
