"""Timeline builder — chronological ordering of file system events."""

import collections
import datetime
from dataclasses import dataclass
from typing import Literal
from .metadata import FileMetadata
from .mft import MFTRecord, TICKS_PER_SECOND

EventKind = Literal['created', 'modified', 'accessed']


@dataclass
class TimelineEvent:
    timestamp: datetime.datetime
    kind: EventKind
    path: str
    size: int
    extension: str
    is_hidden: bool
    is_system: bool


def build_timeline(
    metas: list[FileMetadata],
    include_accessed: bool = False,
) -> list[TimelineEvent]:
    """Convert metadata list into a sorted list of timeline events.

    Access timestamps are excluded by default because many systems update
    them continuously, generating noise that obscures meaningful activity.
    """
    events: list[TimelineEvent] = []

    for m in metas:
        common = dict(path=m.path, size=m.size, extension=m.extension,
                      is_hidden=m.is_hidden, is_system=m.is_system)
        events.append(TimelineEvent(timestamp=m.created,  kind='created',  **common))
        events.append(TimelineEvent(timestamp=m.modified, kind='modified', **common))
        if include_accessed:
            events.append(TimelineEvent(timestamp=m.accessed, kind='accessed', **common))

    events.sort(key=lambda e: e.timestamp)
    return events


def filter_by_range(
    events: list[TimelineEvent],
    start: datetime.datetime,
    end: datetime.datetime,
) -> list[TimelineEvent]:
    return [e for e in events if start <= e.timestamp <= end]


def filter_by_kind(
    events: list[TimelineEvent],
    kind: EventKind,
) -> list[TimelineEvent]:
    return [e for e in events if e.kind == kind]


def group_by_day(events: list[TimelineEvent]) -> dict[datetime.date, list[TimelineEvent]]:
    groups: dict[datetime.date, list[TimelineEvent]] = {}
    for e in events:
        groups.setdefault(e.timestamp.date(), []).append(e)
    return groups


def find_timestamp_anomalies(metas) -> list[dict]:
    """Return files whose OS-reported modified time precedes created time.

    LOW-CONFIDENCE heuristic kept as a fallback for non-NTFS evidence. It
    only sees the timestamps the OS API returns (the $STANDARD_INFORMATION
    set on Windows), which are exactly the ones a timestomping tool
    rewrites, and copying a file legitimately produces the same pattern.
    On Linux/macOS 'created' is the inode-change time, so it is weaker
    still. Use find_si_fn_anomalies() on a parsed $MFT for NTFS evidence.
    """
    anomalies = []
    for m in metas:
        if m.modified < m.created:
            anomalies.append({
                "path": m.path,
                "created": m.created.strftime("%Y-%m-%d %H:%M:%S"),
                "modified": m.modified.strftime("%Y-%m-%d %H:%M:%S"),
                "delta": str(m.created - m.modified).split(".")[0],
                "note": "OS modified before created (low confidence -- also caused by copying)",
            })
    return anomalies


# ── NTFS $STANDARD_INFORMATION vs $FILE_NAME (timestomping) ───────────────────
#
# User-mode APIs (SetFileTime, SetFileInformationByHandle) can rewrite the
# $SI timestamps, but the $FN timestamps are maintained by the NTFS driver
# and are only set when a file is created, renamed or moved. A timestomping
# tool that back-dates a file therefore leaves $SI earlier than $FN, and
# tools that take whole-second input leave $SI with zero sub-second ticks
# while the kernel-written $FN keeps its full 100 ns precision.
#
# Only 'created' and 'mft_changed' are compared for ordering. $SI modified
# earlier than $FN is normal after a copy or archive extraction (the old
# modified time is preserved, $FN gets the copy time), and access times are
# unreliable because last-access updates are often disabled.

#
# Evaluation on a real Windows $MFT (evaluation/RESULTS.md) showed two
# benign sources of alerts, handled as follows:
#   * $SI MFT-changed is often a few milliseconds before $FN MFT-changed
#     while a file is being created -> DEFAULT_TOLERANCE_SECONDS.
#   * Installers (Windows setup, MSI, archive tools) stamp $SI with the
#     package's whole-second build time, which looks exactly like a
#     whole-second timestomp. They stamp MANY files with the SAME value,
#     whereas a back-dated file usually has a unique one, so findings whose
#     $SI Created is shared by >= BULK_THRESHOLD records are 'low' confidence.
#     An attacker who copies a timestamp from a bulk-installed file
#     (timestomp -f) is therefore also rated 'low' -- a known limitation.

_ORDER_FIELDS = (('created', 'Created'), ('mft_changed', 'MFT-changed'))
DEFAULT_TOLERANCE_SECONDS = 2.0
BULK_THRESHOLD = 5


def check_si_fn(record: MFTRecord,
                tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS) -> list[str]:
    """Return the timestomping findings for one MFT record (empty = clean)."""
    si, fn = record.si, record.fn
    if si is None or fn is None:
        return []
    fn_ts = fn.timestamps
    tolerance = int(tolerance_seconds * TICKS_PER_SECOND)
    findings: list[str] = []

    for name, label in _ORDER_FIELDS:
        si_raw, fn_raw = getattr(si, name), getattr(fn_ts, name)
        if si_raw and fn_raw and si_raw < fn_raw - tolerance:
            delta = datetime.timedelta(microseconds=(fn_raw - si_raw) // 10)
            findings.append(f"$SI {label} earlier than $FN {label} by {str(delta).split('.')[0]}")

    si_zero = [n for n in ('created', 'modified', 'mft_changed', 'accessed')
               if si.has_zero_subsecond(n)]
    if len(si_zero) == 4 and not all(fn_ts.has_zero_subsecond(n) for n in si_zero):
        findings.append("All four $SI timestamps have zero sub-second precision; $FN does not")
    elif 'created' in si_zero and fn_ts.subsecond_ticks('created'):
        findings.append("$SI Created has zero sub-second precision; $FN Created does not")

    return findings


def _fmt_ts(ts, name: str) -> str:
    dt = ts.as_datetime(name) if ts else None
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if dt else ''


def find_si_fn_anomalies(
    records: list[MFTRecord],
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    include_deleted: bool = True,
    bulk_threshold: int = BULK_THRESHOLD,
) -> list[dict]:
    """Compare $STANDARD_INFORMATION with $FILE_NAME for every MFT record.

    Each result carries 'confidence': 'high', or 'low' when the record's
    $SI Created value is shared by >= bulk_threshold records (installer or
    bulk-copy pattern). 'shared_by' gives that count.
    """
    shared = collections.Counter(r.si.created for r in records if r.si and r.si.created)
    anomalies = []
    for r in records:
        if not include_deleted and not r.in_use:
            continue
        findings = check_si_fn(r, tolerance_seconds)
        if not findings:
            continue
        fn_ts = r.fn.timestamps
        shared_by = shared[r.si.created]
        confidence = 'low' if shared_by >= bulk_threshold else 'high'
        note = "; ".join(findings)
        if confidence == 'low':
            note += f" [low: $SI Created shared by {shared_by} records -- installer/bulk pattern]"
        anomalies.append({
            "record": r.record_number,
            "path": r.path,
            "in_use": r.in_use,
            "si_created": _fmt_ts(r.si, 'created'),
            "fn_created": _fmt_ts(fn_ts, 'created'),
            "si_modified": _fmt_ts(r.si, 'modified'),
            "fn_modified": _fmt_ts(fn_ts, 'modified'),
            "findings": findings,
            "confidence": confidence,
            "shared_by": shared_by,
            "note": note,
        })
    return anomalies
