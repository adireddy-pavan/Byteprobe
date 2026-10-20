"""Evaluate ByteProbe's NTFS $MFT parser and $SI/$FN timestomping detector.

Uses a real $MFT (13,088 records) from a Windows XP-era NTFS volume, published
as a test sample by the independent `mft` parser project (Apache-2.0):
    https://github.com/omerbenamram/mft/blob/master/samples/MFT

Experiment 1 — Parser accuracy vs. a reference implementation
    Every base record is compared field-by-field with the output of the `mft`
    Rust crate (pip install mft): allocation/directory flags, all four $SI
    timestamps, every $FILE_NAME (name, namespace, parent, four timestamps),
    ADS names and the resolved full path.

Experiment 2 — Detector behaviour on unmodified real data
    How many records the $SI/$FN rules flag with no tampering introduced,
    broken down by rule, so the alert workload on non-injected records is visible.

Experiment 3 — Controlled timestomping injection
    Clean, in-use files are copied and their $SI attribute is rewritten in
    the raw record bytes to simulate five attacker behaviours. The tampered
    $MFT is re-parsed (and re-checked with the reference parser to prove the
    injection landed) and scored by (a) the new $SI/$FN detector and (b) the
    original os.stat baseline (modified < created on the $SI values that the
    Windows API returns).

Usage:
    python evaluation/evaluate_mft.py [path/to/$MFT] [--no-reference]
Writes evaluation/RESULTS.md.
"""

import collections
import os
import random
import struct
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from core import mft                                        # noqa: E402
from core.timeline import (check_si_fn, find_si_fn_anomalies,  # noqa: E402
                           BULK_THRESHOLD, DEFAULT_TOLERANCE_SECONDS)

SAMPLE_URL = 'https://raw.githubusercontent.com/omerbenamram/mft/master/samples/MFT'
SAMPLE_SHA256 = None        # printed at run time for the report
RECORD_SIZE = 1024
TICKS = mft.TICKS_PER_SECOND
DAY = 86400 * TICKS
SEED = 20260930
N_INJECT = 500


def get_sample(path=None):
    if path:
        return path
    local = os.path.join(HERE, 'data', 'MFT')
    if not os.path.exists(local):
        os.makedirs(os.path.dirname(local), exist_ok=True)
        print(f'Downloading sample $MFT from {SAMPLE_URL} …')
        urllib.request.urlretrieve(SAMPLE_URL, local)
    return local


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


# ── Experiment 1 ──────────────────────────────────────────────────────────────

def _ft_to_us(dt):
    """Reference datetimes carry microseconds; compare at that precision.

    A zero FILETIME is reported as None by ByteProbe and as 1601-01-01 by
    the reference; both mean "not set", so they are normalised to None.
    """
    if dt is None or (dt.year == 1601 and dt.month == 1 and dt.day == 1):
        return None
    return dt.replace(tzinfo=None).isoformat()


def _ref_path(full_path):
    """Normalise the reference's path spelling to ByteProbe's."""
    if not full_path or '[UNKNOWN]' in full_path or '[Orphaned]' in full_path:
        return None          # the reference could not resolve it: not compared
    if full_path == '.':
        return '\\'
    return '\\' + full_path.replace('/', '\\')


def reference_view(path):
    import mft as ref   # the independent Rust implementation
    parser = ref.PyMftParser(path)
    base, ext = {}, collections.defaultdict(list)
    for e in parser.entries():
        if isinstance(e, Exception):
            continue
        attrs = [a for a in e.attributes() if not isinstance(a, Exception)]
        flags = {f.strip() for f in str(e.flags).split('(', 1)[-1].rstrip(')').split('|')}
        view = {
            'in_use': 'ALLOCATED' in flags,
            'is_dir': 'INDEX_PRESENT' in flags,    # 0x02; not SPECIAL_INDEX_PRESENT (0x08)
            'si': None, 'fns': [], 'ads': [],
            'path': _ref_path(e.full_path),
        }
        for a in attrs:
            c = a.attribute_content
            if a.type_name == 'StandardInformation':
                view['si'] = tuple(_ft_to_us(getattr(c, n))
                                   for n in ('created', 'modified', 'mft_modified', 'accessed'))
            elif a.type_name == 'FileName':
                view['fns'].append((c.name, c.parent_entry_id, tuple(
                    _ft_to_us(getattr(c, n))
                    for n in ('created', 'modified', 'mft_modified', 'accessed'))))
            elif a.type_name == 'DATA' and a.name:
                view['ads'].append(a.name)
        if e.base_entry_id:
            ext[e.base_entry_id].append(view)
        else:
            base[e.entry_id] = view
    for b, views in ext.items():            # merge extension records like ByteProbe
        if b in base:
            for v in views:
                base[b]['fns'] += v['fns']
                base[b]['ads'] += v['ads']
    return base


def our_view(rec):
    def ts(t):
        return None if t is None else tuple(
            _ft_to_us(t.as_datetime(n)) for n in mft.TIMESTAMP_FIELDS)
    return {
        'in_use': rec.in_use,
        'is_dir': rec.is_directory,
        'si': ts(rec.si),
        'fns': [(f.name, f.parent_record, ts(f.timestamps)) for f in rec.file_names],
        'ads': [a.name for a in rec.ads],
        'path': rec.path,
    }


def experiment_1(path, records):
    t0 = time.perf_counter()
    ref = reference_view(path)
    ref_time = time.perf_counter() - t0

    ours = {r.record_number: our_view(r) for r in records}
    fields = ['in_use', 'is_dir', 'si', 'fns', 'ads', 'path']
    agree = collections.Counter()
    compared = collections.Counter()
    mismatches = collections.defaultdict(list)
    common = sorted(set(ref) & set(ours))
    for n in common:
        a, b = ours[n], ref[n]
        for f in fields:
            if f == 'path' and (b['path'] is None or not a['in_use']):
                continue     # reference leaves deleted/orphan paths unresolved
            compared[f] += 1
            va, vb = a[f], b[f]
            if f in ('fns', 'ads'):
                va, vb = sorted(va), sorted(vb)
            if va == vb:
                agree[f] += 1
            elif len(mismatches[f]) < 5:
                mismatches[f].append((n, va, vb))
    return {
        'ref_records': len(ref), 'our_records': len(ours), 'common': len(common),
        'only_ref': sorted(set(ref) - set(ours))[:10],
        'only_ours': sorted(set(ours) - set(ref))[:10],
        'agree': agree, 'compared': compared, 'mismatches': mismatches,
        'ref_time': ref_time,
    }


# ── Experiment 3 helpers ──────────────────────────────────────────────────────

def si_content_offset(raw: bytes) -> int:
    """Byte offset of the $SI timestamps inside a raw (protected) record."""
    off = struct.unpack_from('<H', raw, 0x14)[0]
    while off + 16 < len(raw):
        atype, alen = struct.unpack_from('<II', raw, off)
        if atype == mft.ATTR_END or alen < 16:
            break
        if atype == mft.ATTR_STANDARD_INFORMATION:
            return off + struct.unpack_from('<H', raw, off + 20)[0]
        off += alen
    raise ValueError('no $SI')


def whole(t):
    return t - t % TICKS


# Each profile: (label, description, fn(si, fn_ts, rnd) -> new $SI tuple)
def _earlier(fn_ts, rnd):
    return fn_ts.created - rnd.randint(30, 5 * 365) * DAY - rnd.randint(0, DAY - 1)


PROFILES = [
    ('A', 'Backdate Created+Modified to a whole-second date '
          '(timestomp.exe / PowerShell `.CreationTime = "2019-01-01 09:00"`)',
     lambda si, fn, r: (whole(_earlier(fn, r)), whole(_earlier(fn, r)),
                        si.mft_changed, si.accessed)),
    ('B', 'Backdate all four $SI values with random sub-second ticks '
          '(careful tool, keeps 100 ns precision)',
     lambda si, fn, r: tuple(_earlier(fn, r) for _ in range(4))),
    ('C', 'Change only $SI Modified to an earlier precise time',
     lambda si, fn, r: (si.created, fn.created - r.randint(1, 900) * DAY - r.randint(1, TICKS - 1),
                        si.mft_changed, si.accessed)),
    ('D', 'Forward-date Created/Modified to a later precise time '
          '(hide a file among newer ones)',
     lambda si, fn, r: tuple(max(si.created, fn.created) + r.randint(1, 400) * DAY
                             + r.randint(1, TICKS - 1) for _ in range(2))
     + (si.mft_changed, si.accessed)),
    ('E', 'Whole-second backdate of $SI AND $FN together '
          '(SetMACE-style / rename trick copies $SI into $FN)',
     None),   # handled specially — also rewrites $FN
    ('F', 'Copy all four $SI values from a random \\\\WINDOWS\\\\system32 file '
          '(`timestomp -f`, `touch -r`)',
     None),   # handled specially — needs a donor record
]


def baseline_flag(si) -> bool:
    """The original tool's check, applied to what the Windows API reports."""
    return si.modified < si.created


def experiment_2(records):
    in_use_files = [r for r in records if r.in_use and r.si and r.fn]
    raw_flagged = [r for r in in_use_files if check_si_fn(r, tolerance_seconds=0)]
    rows = find_si_fn_anomalies(records, include_deleted=False)
    high = [a for a in rows if a['confidence'] == 'high']
    by_rule = collections.Counter()
    for a in rows:
        for x in a['findings']:
            by_rule[x.split(' by ')[0].split(';')[0]] += 1
    base = [r for r in in_use_files if baseline_flag(r.si)]
    top = collections.Counter('\\'.join(a['path'].split('\\')[:3])
                              for a in high).most_common(8)
    return {'n': len(in_use_files), 'raw': raw_flagged, 'rows': rows, 'high': high,
            'by_rule': by_rule, 'baseline': base, 'top': top}


def experiment_3(path, records, use_reference):
    rnd = random.Random(SEED)
    with open(path, 'rb') as f:
        blob = bytearray(f.read())

    candidates = [r for r in records
                  if r.in_use and not r.is_directory and r.si and r.fn and r.fixup_ok
                  and not r.path.startswith('\\$') and not check_si_fn(r)
                  and not baseline_flag(r.si)]
    rnd.shuffle(candidates)
    chosen = candidates[:N_INJECT]
    donors = [r for r in records if r.in_use and r.si and not r.is_directory
              and r.path.lower().startswith('\\windows\\system32\\')]

    # Negative control: untouched clean-looking files must stay clean. The
    # Unlabelled records permit an alert-rate estimate, not a false-positive rate.
    results = {}
    for label, desc, fn_make in PROFILES:
        tampered = bytearray(blob)
        expected = {}
        for rec in chosen:
            start = rec.record_number * RECORD_SIZE
            raw = bytes(tampered[start:start + RECORD_SIZE])
            off = si_content_offset(raw)
            assert off + 32 < 510, 'SI crosses a fixup boundary'
            fn_ts = rec.fn.timestamps
            if label == 'F':
                donor = rnd.choice(donors)
                new_si = (donor.si.created, donor.si.modified,
                          donor.si.mft_changed, donor.si.accessed)
            elif label == 'E':
                t = whole(_earlier(fn_ts, rnd))
                new_si = (t, t, t, t)
                # rewrite every $FN too, as a rename after SetFileTime would
                pos = struct.unpack_from('<H', raw, 0x14)[0]
                while pos + 16 < 510:
                    atype, alen = struct.unpack_from('<II', raw, pos)
                    if atype == mft.ATTR_END or alen < 16:
                        break
                    if atype == mft.ATTR_FILE_NAME:
                        c = pos + struct.unpack_from('<H', raw, pos + 20)[0]
                        struct.pack_into('<4Q', tampered, start + c + 8, *new_si)
                    pos += alen
            else:
                new_si = fn_make(rec.si, fn_ts, rnd)
            struct.pack_into('<4Q', tampered, start + off, *new_si)
            expected[rec.record_number] = new_si

        with tempfile.NamedTemporaryFile(delete=False, suffix='.mft') as tf:
            tf.write(tampered)
            tmp = tf.name
        try:
            parsed = {r.record_number: r for r in mft.parse_mft(tmp)}
            landed = sum(1 for n, si in expected.items()
                         if (parsed[n].si.created, parsed[n].si.modified,
                             parsed[n].si.mft_changed, parsed[n].si.accessed) == tuple(si))
            ref_ok = None
            if use_reference:
                ref = reference_view(tmp)
                ref_ok = sum(1 for n in expected
                             if ref[n]['si'] == our_view(parsed[n])['si'])
            conf = {a['record']: a['confidence']
                    for a in find_si_fn_anomalies(list(parsed.values()))}
            detected = sum(1 for n in expected if n in conf)
            detected_high = sum(1 for n in expected if conf.get(n) == 'high')
            baseline = sum(1 for n in expected if baseline_flag(parsed[n].si))
            untouched = [r for r in records if r.record_number not in expected
                         and r.in_use and r.si and r.fn]
            fp_new = sum(1 for r in untouched if r.record_number in conf)
            fp_high = sum(1 for r in untouched if conf.get(r.record_number) == 'high')
            fp_base = sum(1 for r in untouched if baseline_flag(r.si))
        finally:
            os.unlink(tmp)
        results[label] = dict(desc=desc, n=len(expected), landed=landed, ref_ok=ref_ok,
                              detected=detected, detected_high=detected_high,
                              baseline=baseline, fp_new=fp_new, fp_high=fp_high,
                              fp_base=fp_base, untouched=len(untouched))
    return len(candidates), results


# ── Report ────────────────────────────────────────────────────────────────────

def pct(a, b):
    return f'{100 * a / b:.1f}%' if b else 'n/a'


def main(argv):
    use_reference = '--no-reference' not in argv
    args = [a for a in argv if not a.startswith('--')]
    path = get_sample(args[0] if args else None)
    if use_reference:
        try:
            import mft as _  # noqa: F401
        except ImportError:
            print('Reference parser not installed (pip install mft); skipping comparison.')
            use_reference = False

    out = []
    w = out.append
    w('# ByteProbe NTFS evaluation results\n')
    w(f'- Sample: `{os.path.basename(path)}`, {os.path.getsize(path):,} bytes, '
      f'SHA-256 `{sha256(path)}`')
    w(f'- Source: {SAMPLE_URL}')
    w(f'- Python {sys.version.split()[0]}, random seed {SEED}\n')

    t0 = time.perf_counter()
    records = mft.parse_mft(path)
    our_time = time.perf_counter() - t0
    in_use = sum(r.in_use for r in records)
    w(f'ByteProbe parsed **{len(records):,}** base records ({in_use:,} in use, '
      f'{len(records) - in_use:,} deleted) in **{our_time:.2f} s**; '
      f'{sum(not r.fixup_ok for r in records)} record(s) failed the fixup check; '
      f'{sum(1 for r in records if r.ads)} record(s) carry named $DATA (ADS).\n')

    # Experiment 1
    w('## 1. Parser accuracy compared with an independent reference implementation\n')
    if use_reference:
        e1 = experiment_1(path, records)
        w(f'Reference: `mft` crate (Rust) Python bindings, {e1["ref_time"]:.2f} s. '
          f'Records compared: {e1["common"]:,} '
          f'(reference-only: {e1["only_ref"] or "none"}, '
          f'ByteProbe-only: {e1["only_ours"] or "none"}).\n')
        w('| Field | Agreeing / compared | Agreement |')
        w('|---|---|---|')
        names = {'in_use': 'Allocated (in-use) flag', 'is_dir': 'Directory flag',
                 'si': '$SI timestamps (all four)', 'fns': '$FILE_NAME set (name, parent, 4 timestamps)',
                 'ads': 'ADS names', 'path': 'Full path (in-use records)'}
        for f, label in names.items():
            w(f'| {label} | {e1["agree"][f]:,} / {e1["compared"][f]:,} | '
              f'{pct(e1["agree"][f], e1["compared"][f])} |')
        for f, rows in e1['mismatches'].items():
            w(f'\nExample `{f}` disagreements (record, ByteProbe, reference):')
            for n, a, b in rows:
                w(f'- {n}: `{a}` vs `{b}`')
        w('')
    else:
        w('_Skipped — reference parser not installed (`pip install mft`)._\n')

    # Experiment 2
    e2 = experiment_2(records)
    w('## 2. Alerts on unmodified real data\n')
    n = e2['n']
    w(f'No controlled tampering was introduced in this image, so these alerts measure the observed triage workload on this sample. '
      f'The sample has no independently established per-record tampering ground truth, so no false-positive rate can be inferred. '
      f'Measured on {n:,} in-use records that have both $SI and $FN:\n')
    w('| Method | Records flagged |')
    w('|---|---|')
    w(f'| os.stat baseline (modified < created) | {len(e2["baseline"]):,} ({pct(len(e2["baseline"]), n)}) |')
    w(f'| $SI/$FN rules, no tolerance, no context | {len(e2["raw"]):,} ({pct(len(e2["raw"]), n)}) |')
    w(f'| $SI/$FN rules, {DEFAULT_TOLERANCE_SECONDS:g} s tolerance (all confidences) | '
      f'{len(e2["rows"]):,} ({pct(len(e2["rows"]), n)}) |')
    w(f'| $SI/$FN rules, **high confidence only** (Created value shared by < {BULK_THRESHOLD} records) | '
      f'**{len(e2["high"]):,} ({pct(len(e2["high"]), n)})** |')
    w('\nThe dominant benign cause is Windows setup and other installers. They stamp $SI '
      'Created and Modified with the package build time in whole seconds (e.g. '
      '`2006-02-28 12:00:00` on thousands of XP files), while $FN records the actual install '
      'time. This is exactly the pattern a whole-second timestomp leaves. The tolerance and '
      'high-confidence settings were chosen after inspecting this data set, so the '
      'high-confidence rate is optimistic for other images.\n')
    w('Findings by rule (tolerance applied, all confidences):\n')
    w('| Rule | Records |')
    w('|---|---|')
    for rule, n in e2['by_rule'].most_common():
        w(f'| {rule} | {n:,} |')
    w('\nWhere the high-confidence alerts are (top-level folders):\n')
    for p, n in e2['top']:
        w(f'- `{p}`: {n:,}')
    w('')

    # Experiment 3
    n_cand, e3 = experiment_3(path, records, use_reference)
    w('## 3. Controlled timestomping injection\n')
    w(f'{N_INJECT} in-use files were sampled from {n_cand:,} files that neither method flags. '
      'Each attack profile rewrites the $SI bytes of those records in a copy of the $MFT. '
      'The copy is then re-parsed. "Landed" confirms that ByteProbe reads back exactly the '
      'injected values; "Reference agrees" confirms that the independent parser sees the '
      'same values.\n')
    w('Detection rate on the tampered files:\n')
    w('| Profile | Attack | Landed | Reference agrees | $SI/$FN (any) | '
      '$SI/$FN (high confidence) | os.stat baseline |')
    w('|---|---|---|---|---|---|---|')
    for label, r in e3.items():
        ref = f'{r["ref_ok"]}/{r["n"]}' if r['ref_ok'] is not None else 'skipped'
        w(f'| {label} | {r["desc"]} | {r["landed"]}/{r["n"]} | {ref} | '
          f'{pct(r["detected"], r["n"])} | **{pct(r["detected_high"], r["n"])}** | '
          f'{pct(r["baseline"], r["n"])} |')
    r = next(iter(e3.values()))
    w(f'\nAlert rate on the {r["untouched"]:,} non-injected in-use records of the same '
      f'volume: $SI/$FN any = {pct(r["fp_new"], r["untouched"])}, '
      f'$SI/$FN high confidence = **{pct(r["fp_high"], r["untouched"])}**, '
      f'os.stat baseline = {pct(r["fp_base"], r["untouched"])}.\n')
    w('\nInterpretation:\n'
      '- **A and B** are the attacks the report describes: back-dating a file with a '
      'user-mode API. The $SI/$FN comparison catches them because $FN still holds the '
      'real creation time. The baseline only fires if the attacker happens to set Modified '
      'earlier than Created.\n'
      '- **C** (only Modified moved earlier) is invisible to the $SI/$FN detector by design. '
      'Modified is excluded from the ordering rule because copying or extracting a file '
      'legitimately preserves an old Modified time. The os.stat baseline catches C, but it '
      'flags approximately 20% of non-injected records in this sample (not a verified false-positive rate), so the two checks are '
      'complementary. That is why ByteProbe keeps both.\n'
      '- **D** (forward-dating) and **E** (where $FN is also rewritten, e.g. SetMACE or a '
      'rename after stomping) defeat the $SI/$FN comparison. Detecting them needs '
      '$UsnJrnl/$LogFile correlation, which ByteProbe does not implement.\n'
      '- **F** (copying timestamps from a system file) is still caught by the ordering rule, '
      'because the donor is older than the target\'s $FN. However, it is usually downgraded to '
      'low confidence, because the copied value is a bulk installer timestamp. That is the '
      'price of the noise suppression, and an attacker who knows the rule can exploit it.\n'
      '- Candidate files were chosen from those that neither method flagged beforehand, so '
      'detections come from the injection alone. The baseline figure for A/B/D depends on '
      'whether the random dates happen to put Modified before Created.\n')

    report = '\n'.join(out)
    with open(os.path.join(HERE, 'RESULTS.md'), 'w', encoding='utf-8') as f:
        f.write(report + '\n')
    print(report)


if __name__ == '__main__':
    main(sys.argv[1:])
