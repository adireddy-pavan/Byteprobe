"""NTFS Master File Table ($MFT) parser — $STANDARD_INFORMATION, $FILE_NAME, $DATA.

Accepted sources (auto-detected):
  * an extracted $MFT file (exported with FTK Imager, icat, MFTECmd, ...)
  * a raw NTFS volume image (dd / .raw / .img), or a whole-disk raw image
    whose NTFS partition is located through the MBR or GPT partition table
  * a live NTFS volume on Windows, e.g. r'\\\\.\\C:' (Administrator required)

For every FILE record the parser returns:
  * $STANDARD_INFORMATION (0x10) — created, modified, MFT-changed, accessed
  * every $FILE_NAME (0x30)      — the same four timestamps, name, parent ref
  * every $DATA (0x80)           — named $DATA attributes are Alternate Data
                                   Streams, which gives ADS detection that
                                   works on any OS when reading an image

Timestamps are kept as raw FILETIME integers (100 ns ticks since
1601-01-01 UTC) so sub-second precision is never lost; this matters for
timestomping detection (see core/timeline.find_si_fn_anomalies).

Read-only: the source is opened 'rb' and never written to.

Known limitations:
  * E01/AFF images are not supported — convert to raw first (ewfexport).
  * Attributes held in extension records are merged into their base record,
    but the $ATTRIBUTE_LIST attribute itself is not interpreted.
  * $LogFile / $UsnJrnl are not parsed; only the current MFT state is seen.
"""

import datetime
import ntpath
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Iterator, Optional

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME            = 0x30
ATTR_DATA                 = 0x80
ATTR_END                  = 0xFFFFFFFF

RECORD_IN_USE    = 0x0001
RECORD_DIRECTORY = 0x0002

# $FILE_NAME namespaces
NS_POSIX, NS_WIN32, NS_DOS, NS_WIN32_DOS = 0, 1, 2, 3
_NS_PREFERENCE = {NS_WIN32: 0, NS_WIN32_DOS: 0, NS_POSIX: 1, NS_DOS: 2}

ROOT_RECORD      = 5
ORPHAN_PREFIX    = '\\$OrphanFiles'
TICKS_PER_SECOND = 10_000_000
TIMESTAMP_FIELDS = ('created', 'modified', 'mft_changed', 'accessed')

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_READ_CHUNK     = 1 << 20   # 1 MiB — a multiple of every sector/record size


class MFTError(Exception):
    """Raised when the source is not a readable $MFT / NTFS volume."""


# ── Data model ────────────────────────────────────────────────────────────────

def filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    """Convert a FILETIME to an aware UTC datetime (microsecond precision)."""
    if not ft:
        return None
    try:
        return _FILETIME_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


@dataclass(slots=True)
class NTFSTimestamps:
    """The four NTFS timestamps (MACB) as raw FILETIME values."""
    created:     int
    modified:    int
    mft_changed: int
    accessed:    int

    def as_datetime(self, name: str) -> Optional[datetime.datetime]:
        return filetime_to_datetime(getattr(self, name))

    def subsecond_ticks(self, name: str) -> int:
        """The 100 ns ticks below one second (0-9,999,999)."""
        return getattr(self, name) % TICKS_PER_SECOND

    def has_zero_subsecond(self, name: str) -> bool:
        raw = getattr(self, name)
        return raw != 0 and raw % TICKS_PER_SECOND == 0


@dataclass(slots=True)
class FileNameAttr:
    name:            str
    namespace:       int
    parent_record:   int
    parent_sequence: int
    timestamps:      NTFSTimestamps


@dataclass(slots=True)
class DataStream:
    name:     str      # '' for the default (unnamed) stream, otherwise an ADS
    size:     int      # logical size in bytes
    resident: bool
    runs:     list = field(default_factory=list)   # [(lcn|None, clusters)]


@dataclass(slots=True)
class MFTRecord:
    record_number: int
    sequence:      int
    in_use:        bool
    is_directory:  bool
    base_record:   int                  # 0 for base records
    fixup_ok:      bool                 # False = torn/corrupt sector
    si:            Optional[NTFSTimestamps] = None
    file_names:    list = field(default_factory=list)
    data_streams:  list = field(default_factory=list)
    path:          str = ''

    @property
    def fn(self) -> Optional[FileNameAttr]:
        """The $FILE_NAME to display: Win32 name preferred over DOS 8.3."""
        if not self.file_names:
            return None
        return min(self.file_names, key=lambda f: _NS_PREFERENCE.get(f.namespace, 3))

    @property
    def name(self) -> str:
        fn = self.fn
        return fn.name if fn else ''

    @property
    def ads(self) -> list[DataStream]:
        return [d for d in self.data_streams if d.name]

    @property
    def data_size(self) -> Optional[int]:
        for d in self.data_streams:
            if not d.name:
                return d.size
        return None


# ── Low-level structures ──────────────────────────────────────────────────────

def apply_fixup(buf: bytearray) -> bool:
    """Apply the update sequence array in place.

    NTFS replaces the last two bytes of every 512-byte stride of a record
    with an update sequence number (USN) and stores the real bytes in the
    array. A mismatching USN means the record was only partly written.
    """
    usa_off, usa_count = struct.unpack_from('<HH', buf, 4)
    if usa_count < 2:
        return True
    if usa_off + usa_count * 2 > len(buf):
        return False
    stride = len(buf) // (usa_count - 1)
    usn = bytes(buf[usa_off:usa_off + 2])
    ok = True
    for i in range(1, usa_count):
        end = i * stride
        if end > len(buf):
            break
        if buf[end - 2:end] != usn:
            ok = False
        buf[end - 2:end] = buf[usa_off + 2 * i:usa_off + 2 * i + 2]
    return ok


def decode_runlist(data: bytes) -> list[tuple[Optional[int], int]]:
    """Decode a non-resident attribute's data runs into (lcn, clusters).

    Each run starts with a header byte: low nibble = size of the length
    field, high nibble = size of the (signed, relative) LCN offset field.
    An offset size of 0 marks a sparse run, returned with lcn None.
    """
    runs: list[tuple[Optional[int], int]] = []
    pos, lcn = 0, 0
    while pos < len(data) and data[pos]:
        len_size, off_size = data[pos] & 0x0F, data[pos] >> 4
        pos += 1
        if not len_size or pos + len_size + off_size > len(data):
            raise MFTError('Corrupt data run list')
        length = int.from_bytes(data[pos:pos + len_size], 'little')
        pos += len_size
        if off_size:
            lcn += int.from_bytes(data[pos:pos + off_size], 'little', signed=True)
            pos += off_size
            runs.append((lcn, length))
        else:
            runs.append((None, length))
    return runs


def _parse_timestamps(content: bytes, offset: int) -> NTFSTimestamps:
    return NTFSTimestamps(*struct.unpack_from('<4Q', content, offset))


def parse_record(data: bytes, record_number: Optional[int] = None) -> Optional[MFTRecord]:
    """Parse one FILE record. Returns None for empty or non-FILE slots."""
    if len(data) < 48 or data[:4] != b'FILE':
        return None
    buf = bytearray(data)
    fixup_ok = apply_fixup(buf)

    usa_off = struct.unpack_from('<H', buf, 4)[0]
    sequence = struct.unpack_from('<H', buf, 0x10)[0]
    attr_off, flags = struct.unpack_from('<HH', buf, 0x14)
    used_size = struct.unpack_from('<I', buf, 0x18)[0]
    base_ref  = struct.unpack_from('<Q', buf, 0x20)[0]
    if record_number is None:
        # NTFS 3.1+ stores the record number in the header
        record_number = struct.unpack_from('<I', buf, 0x2C)[0] if usa_off >= 0x30 else -1

    rec = MFTRecord(
        record_number=record_number,
        sequence=sequence,
        in_use=bool(flags & RECORD_IN_USE),
        is_directory=bool(flags & RECORD_DIRECTORY),
        base_record=base_ref & 0xFFFFFFFFFFFF,
        fixup_ok=fixup_ok,
    )

    limit = min(used_size, len(buf)) if used_size else len(buf)
    off = attr_off
    while off + 16 <= limit:
        atype, alen = struct.unpack_from('<II', buf, off)
        if atype == ATTR_END or alen < 16 or off + alen > limit:
            break
        non_resident = buf[off + 8]
        name_len     = buf[off + 9]
        name_off     = struct.unpack_from('<H', buf, off + 10)[0]
        attr_name    = bytes(buf[off + name_off:off + name_off + name_len * 2]
                             ).decode('utf-16-le', 'replace')

        content = b''
        if not non_resident:
            csize, coff = struct.unpack_from('<IH', buf, off + 16)
            content = bytes(buf[off + coff:off + coff + csize])

        if atype == ATTR_STANDARD_INFORMATION and len(content) >= 32:
            rec.si = _parse_timestamps(content, 0)

        elif atype == ATTR_FILE_NAME and len(content) >= 66:
            parent_ref = struct.unpack_from('<Q', content, 0)[0]
            n = content[64]
            rec.file_names.append(FileNameAttr(
                name=content[66:66 + n * 2].decode('utf-16-le', 'replace'),
                namespace=content[65],
                parent_record=parent_ref & 0xFFFFFFFFFFFF,
                parent_sequence=parent_ref >> 48,
                timestamps=_parse_timestamps(content, 8),
            ))

        elif atype == ATTR_DATA:
            if not non_resident:
                rec.data_streams.append(DataStream(attr_name, len(content), True))
            else:
                start_vcn = struct.unpack_from('<Q', buf, off + 0x10)[0]
                run_off   = struct.unpack_from('<H', buf, off + 0x20)[0]
                real_size = struct.unpack_from('<Q', buf, off + 0x30)[0]
                try:
                    runs = decode_runlist(bytes(buf[off + run_off:off + alen]))
                except MFTError:
                    runs = []
                if start_vcn == 0:   # later fragments repeat the stream
                    rec.data_streams.append(DataStream(attr_name, real_size, False, runs))

        off += alen

    return rec


# ── Volume geometry ───────────────────────────────────────────────────────────

@dataclass(slots=True)
class NTFSBootSector:
    bytes_per_sector:    int
    sectors_per_cluster: int
    mft_lcn:             int
    record_size:         int
    volume_offset:       int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


def is_ntfs_boot_sector(data: bytes) -> bool:
    return len(data) >= 512 and data[3:11] == b'NTFS    '


def parse_boot_sector(data: bytes, volume_offset: int = 0) -> NTFSBootSector:
    if not is_ntfs_boot_sector(data):
        raise MFTError('Not an NTFS boot sector')
    bps = struct.unpack_from('<H', data, 0x0B)[0]
    spc = data[0x0D]
    if spc > 0x80:                          # large clusters stored as 2^-n
        spc = 1 << (256 - spc)
    mft_lcn = struct.unpack_from('<Q', data, 0x30)[0]
    cpr = struct.unpack_from('<b', data, 0x40)[0]
    record_size = cpr * bps * spc if cpr > 0 else 1 << -cpr
    if not bps or not spc or record_size < 256:
        raise MFTError('Implausible NTFS geometry in boot sector')
    return NTFSBootSector(bps, spc, mft_lcn, record_size, volume_offset)


def _read_at(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    return f.read(size)


def find_ntfs_partitions(f: BinaryIO) -> list[int]:
    """Return byte offsets of NTFS volumes listed in an MBR or GPT table."""
    offsets: list[int] = []
    mbr = _read_at(f, 0, 512)
    if len(mbr) < 512 or mbr[510:512] != b'\x55\xaa':
        return offsets

    gpt = _read_at(f, 512, 512)
    if gpt[:8] == b'EFI PART':
        entries_lba, count, entry_size = struct.unpack_from('<QII', gpt, 72)
        table = _read_at(f, entries_lba * 512, min(count, 256) * entry_size)
        starts = [struct.unpack_from('<Q', table, i * entry_size + 32)[0]
                  for i in range(len(table) // entry_size)
                  if table[i * entry_size:i * entry_size + 16] != bytes(16)]
    else:
        starts = [struct.unpack_from('<I', mbr, 446 + i * 16 + 8)[0]
                  for i in range(4) if mbr[446 + i * 16 + 4]]

    for lba in starts:
        if lba and is_ntfs_boot_sector(_read_at(f, lba * 512, 512)):
            offsets.append(lba * 512)
    return offsets


def normalise_source(source: str) -> str:
    """Accept 'C:' or 'C:\\' for a live Windows volume."""
    s = source.strip()
    if len(s) in (2, 3) and s[1] == ':' and s[0].isalpha() and s[2:] in ('', '\\', '/'):
        return f'\\\\.\\{s[0].upper()}:'
    return s


# ── Record iteration ──────────────────────────────────────────────────────────

def _iter_extracted(f: BinaryIO, first: bytes) -> Iterator[tuple[int, bytes]]:
    record_size = struct.unpack_from('<I', first, 0x1C)[0] or 1024
    if record_size not in (1024, 2048, 4096):
        record_size = 1024
    f.seek(0)
    number = 0
    while chunk := f.read(_READ_CHUNK - _READ_CHUNK % record_size):
        for i in range(0, len(chunk) - record_size + 1, record_size):
            yield number, chunk[i:i + record_size]
            number += 1


def _iter_volume(f: BinaryIO, boot: NTFSBootSector) -> Iterator[tuple[int, bytes]]:
    cs, rs = boot.cluster_size, boot.record_size
    mft_start = boot.volume_offset + boot.mft_lcn * cs
    rec0 = parse_record(_read_at(f, mft_start, rs), 0)
    if rec0 is None:
        raise MFTError('Record 0 ($MFT) not found at the boot-sector MFT location')
    data = next((d for d in rec0.data_streams if not d.name and not d.resident), None)
    if data is None or not data.runs:
        raise MFTError('$MFT has no non-resident $DATA run list')

    total = data.size // rs
    number = 0
    for lcn, clusters in data.runs:
        run_bytes = clusters * cs
        if lcn is None:                     # sparse run: no records stored
            number += run_bytes // rs
            continue
        pos, end = boot.volume_offset + lcn * cs, boot.volume_offset + (lcn + clusters) * cs
        while pos < end and number < total:
            chunk = _read_at(f, pos, min(_READ_CHUNK, end - pos))
            if not chunk:
                return
            for i in range(0, len(chunk) - rs + 1, rs):
                if number >= total:
                    return
                yield number, chunk[i:i + rs]
                number += 1
            pos += len(chunk)


def iter_raw_records(source: str, volume_offset: Optional[int] = None
                     ) -> Iterator[tuple[int, bytes]]:
    """Yield (record_number, raw_bytes) from any supported source."""
    source = normalise_source(source)
    try:
        f = open(source, 'rb', buffering=0)
    except PermissionError as exc:
        raise MFTError(f'Access denied opening {source} — run as Administrator') from exc
    except OSError as exc:
        raise MFTError(f'Cannot open {source}: {exc}') from exc

    with f:
        start = volume_offset or 0
        head = _read_at(f, start, 512)
        if head[:4] == b'FILE' and volume_offset is None:
            yield from _iter_extracted(f, head)
            return
        if is_ntfs_boot_sector(head):
            yield from _iter_volume(f, parse_boot_sector(head, start))
            return
        if volume_offset is None:
            parts = find_ntfs_partitions(f)
            if parts:
                boot = parse_boot_sector(_read_at(f, parts[0], 512), parts[0])
                yield from _iter_volume(f, boot)
                return
        raise MFTError('Source is neither an extracted $MFT nor an NTFS volume/disk image')


# ── High-level API ────────────────────────────────────────────────────────────

def build_paths(records: dict[int, MFTRecord]) -> None:
    """Resolve full paths by walking $FILE_NAME parent references to root."""
    paths: dict[int, str] = {ROOT_RECORD: ''}
    for num in records:
        stack: list[int] = []
        cur, broken = num, False
        while cur not in paths:
            rec = records.get(cur)
            if rec is None or rec.fn is None or cur in stack:
                broken = True
                break
            stack.append(cur)
            parent = records.get(rec.fn.parent_record)
            # Parent slot reused by a different file -> this path is stale
            if parent is not None and parent.in_use and \
                    parent.sequence != rec.fn.parent_sequence:
                broken = True
                break
            cur = rec.fn.parent_record
        base = ORPHAN_PREFIX if broken else paths[cur]
        for n in reversed(stack):
            base = f'{base}\\{records[n].fn.name}'
            paths[n] = base
    for num, rec in records.items():
        rec.path = '\\' if num == ROOT_RECORD else paths.get(num, '')


def parse_mft(
    source: str,
    volume_offset: Optional[int] = None,
    include_deleted: bool = True,
    progress_cb: Optional[Callable[[int], None]] = None,
    cancel_flag=None,
) -> list[MFTRecord]:
    """Parse every FILE record, merge extension records, resolve paths."""
    records: dict[int, MFTRecord] = {}
    for number, raw in iter_raw_records(source, volume_offset):
        if cancel_flag is not None and cancel_flag.is_set():
            break
        rec = parse_record(raw, number)
        if rec is not None:
            records[number] = rec
        if progress_cb and number % 4096 == 0:
            progress_cb(number)

    # Attributes that overflowed into extension records belong to the base
    for num, rec in list(records.items()):
        base = records.get(rec.base_record) if rec.base_record else None
        if base is not None and base is not rec:
            base.file_names.extend(rec.file_names)
            base.data_streams.extend(rec.data_streams)
            if base.si is None:
                base.si = rec.si
            del records[num]

    build_paths(records)
    return [r for r in records.values() if include_deleted or r.in_use]


# ── Matching MFT records to files found by the directory scan ────────────────

def _norm_key(path: str) -> str:
    return '\\' + path.replace('/', '\\').strip('\\').lower()


class MFTIndex:
    """Look up the MFT record for a file found by the directory scan.

    A candidate is accepted only when its $DATA size equals the scanned
    file's size, so an unrelated image cannot be matched on name alone.
    """

    def __init__(self, records: list[MFTRecord]):
        self._by_path: dict[str, MFTRecord] = {}
        for r in records:
            if r.in_use and not r.is_directory and r.path:
                self._by_path[_norm_key(r.path)] = r

    def __len__(self) -> int:
        return len(self._by_path)

    def lookup(self, file_path: str, size: Optional[int] = None,
               scan_root: Optional[str] = None) -> Optional[MFTRecord]:
        keys = [_norm_key(ntpath.splitdrive(file_path)[1])]
        if scan_root:
            # metadata.py stores resolved paths, so also try the resolved root
            # (e.g. macOS /var -> /private/var)
            for root in dict.fromkeys((scan_root, os.path.realpath(scan_root))):
                rel = os.path.relpath(file_path, root)
                if not rel.startswith('..'):
                    keys.append(_norm_key(rel))
        for key in keys:
            rec = self._by_path.get(key)
            if rec is not None and (size is None or rec.data_size in (None, size)):
                return rec
        return None
