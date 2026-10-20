"""Audit a ByteProbe $MFT parse against a separately generated MFTECmd CSV.

Run MFTECmd independently on the EXACT SAME extracted $MFT:
    MFTECmd.exe -f C:\\Evidence\\$MFT --csv C:\\Evidence\\ref --csvf reference.csv --at
Then, from the project root:
    python evaluation/compare_mftecmd.py "$MFT" reference.csv --out evaluation/comparison

No benchmark result is claimed unless both data sources are actually provided.
Matching key = (EntryNumber, SequenceNumber), not path alone.
Timestamps are compared at microsecond resolution because Python datetime does
not preserve NTFS FILETIME's final 100 ns digit. Times are interpreted as UTC;
verify that the reference export has not been shifted to local time.

Rows labelled IsAds=True are not compared as file base records; parent filename
variants are de-duplicated conservatively by entry/sequence key. Ambiguous
reference rows, missing data, and path differences are recorded rather than
being counted as agreement.
"""

import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.mft import parse_mft

FIELDS = {
    'in_use': 'InUse', 'is_directory': 'IsDirectory',
    'created_si': 'Created0x10', 'modified_si': 'LastModified0x10',
    'changed_si': 'LastRecordChange0x10', 'accessed_si': 'LastAccess0x10',
    'created_fn': 'Created0x30', 'modified_fn': 'LastModified0x30',
    'changed_fn': 'LastRecordChange0x30', 'accessed_fn': 'LastAccess0x30',
}
REQUIRED = {'EntryNumber', 'SequenceNumber', 'InUse', 'IsDirectory'}
TS_FIELDS = {k for k in FIELDS if k.endswith('_si') or k.endswith('_fn')}


def _digest(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _bool(s):
    x = str(s).strip().lower()
    if x in ('true', '1', 'yes'): return True
    if x in ('false', '0', 'no'): return False
    return None


def _time(s):
    """Normalise MFTECmd seven-digit UTC timestamps to Python microseconds.

    MFTECmd may emit explicit UTC offsets; never strip the offset digits as
    if they were fractional seconds. Offset-free values are *assumed* UTC
    and must be checked against the source tool's configuration.
    """
    s = (s or '').strip()
    if not s or s.startswith('0001-01-01') or s.startswith('1601-01-01'):
        return None
    try:
        value = dt.datetime.fromisoformat(s)
        if value.tzinfo is not None:
            value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return value.isoformat(timespec='microseconds')
    except ValueError as exc:
        raise ValueError(f'Unsupported datetime in reference CSV: {s!r}') from exc


def load_ref(csv_path):
    result = {}
    duplicate = set()
    ads_rows = 0
    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        missing = REQUIRED.difference(reader.fieldnames or [])
        if missing: raise ValueError('Reference CSV missing columns: ' + ', '.join(sorted(missing)))
        for row in reader:
            if _bool(row.get('IsAds', '')) is True:
                ads_rows += 1
                continue
            key = (int(row['EntryNumber']), int(row['SequenceNumber']))
            if key in result:
                duplicate.add(key)
            else:
                result[key] = row
    # Never select an arbitrary row if the independent tool emitted multiple
    # non-ADS filename entries for the same record: flag ambiguity explicitly.
    return result, duplicate, ads_rows


def ours(rec):
    si = rec.si
    fn = rec.fn.timestamps if rec.fn else None
    out = {'in_use': rec.in_use, 'is_directory': rec.is_directory}
    for label, obj in (('si', si), ('fn', fn)):
        for k, attr in (('created', 'created'), ('modified', 'modified'),
                        ('changed', 'mft_changed'), ('accessed', 'accessed')):
            value = obj.as_datetime(attr) if obj else None
            if value is not None:
                value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
                value = value.isoformat(timespec='microseconds')
            out[f'{k}_{label}'] = value
    return out


def compare(mft_file, csv_file, outdir):
    records = {(r.record_number, r.sequence): r for r in parse_mft(str(mft_file))}
    ref, duplicates, ads_rows = load_ref(csv_file)
    common = sorted(set(records) & set(ref))
    counts = collections.defaultdict(lambda: {'agree': 0, 'disagree': 0, 'excluded': 0})
    differences = []
    for key in common:
        if key in duplicates:
            differences.append([*key, 'record', 'AMBIGUOUS_REFERENCE', '', 'Multiple non-ADS CSV rows'])
            for field in FIELDS: counts[field]['excluded'] += 1
            continue
        b = ours(records[key]); a = ref[key]
        for field, column in FIELDS.items():
            if column not in a or not str(a[column]).strip():
                counts[field]['excluded'] += 1
                continue
            observed = _time(a[column]) if field in TS_FIELDS else _bool(a[column])
            if observed is None and field not in TS_FIELDS:
                counts[field]['excluded'] += 1
                continue
            expected = b[field]
            if expected == observed:
                counts[field]['agree'] += 1
            else:
                counts[field]['disagree'] += 1
                differences.append([*key, field, expected, observed, ''])
    summary = {
        'byteprobe_input_sha256': _digest(mft_file),
        'reference_csv_sha256': _digest(csv_file),
        'byteprobe_record_keys': len(records), 'reference_record_keys': len(ref),
        'common_record_keys': len(common),
        'reference_key_coverage': round(len(common) / len(ref), 6) if ref else 0.0,
        'byteprobe_key_coverage': round(len(common) / len(records), 6) if records else 0.0,
        'only_in_byteprobe': len(set(records) - set(ref)),
        'only_in_reference': len(set(ref) - set(records)),
        'ambiguous_reference_keys': len(duplicates),
        'reference_ads_rows_excluded': ads_rows,
        'fields': dict(counts),
        'comparability': 'Identical extracted $MFT required; reference timestamps assumed UTC; comparisons at 1 microsecond precision; blank fields excluded; ambiguous keys excluded',
    }
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    with open(outdir / 'unmatched_record_keys.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['EntryNumber', 'SequenceNumber', 'PresentOnlyIn'])
        for key in sorted(set(records) - set(ref)):
            w.writerow([*key, 'ByteProbe'])
        for key in sorted(set(ref) - set(records)):
            w.writerow([*key, 'MFTECmd'])
    with open(outdir / 'discrepancies.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['EntryNumber', 'SequenceNumber', 'Field', 'ByteProbe', 'MFTECmd', 'Note'])
        w.writerows(differences)
    with open(outdir / 'summary.json', 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    with open(outdir / 'summary.md', 'w', encoding='utf-8') as f:
        f.write('# Independent MFTECmd comparison\n\n')
        f.write('Both tools must have processed the identical $MFT. Check hashes and record command/version separately.\n\n')
        f.write(f"Common record+sequence keys: **{len(common)}**; ambiguous keys: **{len(duplicates)}**.\n\n")
        f.write('| Field | Agree | Disagree | Excluded | Agreement on compared |\n|---|---:|---:|---:|---:|\n')
        for field, c in counts.items():
            n = c['agree'] + c['disagree']
            f.write(f"| {field} | {c['agree']} | {c['disagree']} | {c['excluded']} | {c['agree']/n*100:.2f}% |\n" if n else f"| {field} | 0 | 0 | {c['excluded']} | n/a |\n")
        f.write('\nReport missing records, disagreements, uncomparable fields and tool versions; never imply certification.\n')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('mft', help='Extracted $MFT file (exact file supplied independently to MFTECmd)')
    p.add_argument('reference_csv', help='MFTECmd --csv export from that same extracted $MFT')
    p.add_argument('--out', default='evaluation/comparison', help='Directory for summary and all discrepancies')
    args = p.parse_args()
    s = compare(args.mft, args.reference_csv, args.out)
    print(json.dumps(s, indent=2))

if __name__ == '__main__': main()
