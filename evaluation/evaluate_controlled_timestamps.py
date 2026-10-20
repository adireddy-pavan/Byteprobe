"""Controlled, fully labelled NTFS timestamp experiment with benign lookalikes.

This is an AUTHOR-CONSTRUCTED adversarial test, not an independently blinded
experiment and not representative of prevalence on actual Windows volumes.
It exposes the trade-off between benign timestamp inconsistency, suppression,
and missed tampering. Labels are known because the generator creates the data.

Usage:
    python evaluation/evaluate_controlled_timestamps.py
Produces RESULTS_CONTROLLED_TIMESTAMPS.md and controlled_timestamps.csv.
"""
import collections
import csv
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import mft
from core.timeline import find_si_fn_anomalies
from tests import ntfs_builder as nb

HERE = Path(__file__).parent
N = 80
TICKS = 10_000_000
BASE = nb.filetime(2022, 7, 14, 15, 0, 0, ticks=1200000)
OLDER = nb.filetime(2017, 2, 1, 8, 30, 0)


def wilson(success, total):
    if not total: return (0.0, 0.0)
    z = 1.959963984540054
    p = success / total
    q = z*z / total
    half = z / (1+q) * math.sqrt(p*(1-p)/total + z*z/(4*total*total))
    center = (p + q/2) / (1+q)
    return (max(0., center-half), min(1., center+half))


def build_fixture():
    """Known label and profile for each synthetically constructed record."""
    rows = []
    records = []
    next_no = 20
    profiles = ['benign_identical', 'benign_old_modified_copy',
                'benign_bulk_installer', 'benign_unique_old_created',
                'A', 'B', 'C', 'D', 'E', 'F']
    for profile in profiles:
        total = 40 if profile.startswith('benign_') else N
        for i in range(total):
            nr = next_no; next_no += 1
            new = BASE + (nr * 239)  # unique sub-second precision, fixed seed
            fn = [new, new+5, new+10, new+15]
            si = fn[:]
            if profile == 'benign_old_modified_copy':
                si[1] = new - 25 * 86400 * TICKS
            elif profile == 'benign_bulk_installer':
                # 20 share a very common installer date; 20 form
                # four smaller (five-file) setup cohorts.
                t = OLDER if i < 20 else OLDER + (100 + (i-20)//5)*TICKS
                si[0] = t
                si[1] = t
            elif profile == 'benign_unique_old_created':
                si[0] = OLDER + (i+1)*TICKS    # one distinct second per file
                si[1] = si[0]
            elif profile == 'A':
                si[0] = OLDER + (i+200)*TICKS    # created and modified backdated
                si[1] = si[0]
            elif profile == 'B':
                t = OLDER + (i+1)*TICKS + 1_234_567
                si = [t, t+10, t+20, t+30]
            elif profile == 'C':
                si[1] = new - 300 * 86400 * TICKS + 123
            elif profile == 'D':
                t = new + 180 * 86400 * TICKS + 123
                si[0], si[1] = t, t+11
            elif profile == 'E':
                t = OLDER + (i+400)*TICKS
                si, fn = [t]*4, [t]*4  # coordinated rewriting
            elif profile == 'F':
                # 30 copy a common timestamp; 30 copy among five
                # moderately shared donors; 20 use unique donors.
                t = (OLDER if i < 30 else
                     OLDER + (600 + (i-30)//6)*TICKS if i < 60 else
                     OLDER + (700+i)*TICKS + 55)
                si = [t, t+5, t+10, t+15]
            assert len(si) == len(fn) == 4
            data = nb.make_record(nr, [nb.si_attr(*si), nb.fn_attr(f'file_{nr}.bin', 5, fn, parent_seq=5)])
            rec = mft.parse_record(data, nr)
            rec.path = f'\\controlled\\{profile}\\file_{nr}.bin'
            records.append(rec)
            rows.append({'record': nr, 'profile': profile,
                         'true_tampered': not profile.startswith('benign_')})
    return records, rows


def evaluate(records, rows, tolerance, bulk_threshold):
    findings = find_si_fn_anomalies(records, tolerance_seconds=tolerance,
                                    include_deleted=False, bulk_threshold=bulk_threshold)
    confidence = {a['record']: a['confidence'] for a in findings}
    counts = collections.defaultdict(lambda: {'n': 0, 'any': 0, 'high': 0})
    entries = []
    for row in rows:
        cat = row['profile']
        flagged = row['record'] in confidence
        high = confidence.get(row['record']) == 'high'
        counts[cat]['n'] += 1
        counts[cat]['any'] += int(flagged)
        counts[cat]['high'] += int(high)
        entries.append({**row, 'tolerance': tolerance, 'bulk_threshold': bulk_threshold,
                        'flag_any': flagged, 'flag_high': high,
                        'confidence': confidence.get(row['record'], 'none')})
    return counts, entries


def main():
    records, rows = build_fixture()
    headings = ['# Controlled NTFS timestamp stress test', '',
        'All observations below are on **author-built NTFS FILE records with assigned labels**. '
        'These results are reproducible checks of detector logic, not a real-world sensitivity, '
        'specificity, or attacker-prevalence estimate. The benign controls intentionally include '
        'copy/extraction and installer-like timestamp patterns. They are not representative random samples.', '',
        f'- {len(records)} labelled synthetic records: {sum(not r["true_tampered"] for r in rows)} benign, '
        f'{sum(r["true_tampered"] for r in rows)} modified',
        '- Profiles A–F each contain 80 records; benign controls include 40 each of identical, '
        'Modified-preserving copy, bulk-installer style (including five-file cohorts), and unique older-created extraction',
        '- The same constructed records are scored at tolerance 0, 2 and 5 seconds and '
        'bulk threshold 3, 5 and 10 without choosing a winning threshold',
        '- The Wilson 95% interval illustrates finite sample uncertainty within the constructed '
        'scenarios only; it cannot correct selection bias or confer external validity.', '',
        '## Baseline policy (2 seconds tolerance, threshold 5)', '',
        '| Ground-truth profile | N | Any-alert n (%) | High-alert n (%) | High-alert 95% Wilson interval |',
        '|---|---:|---:|---:|---:|']
    baseline, entry = evaluate(records, rows, 2, 5)
    for cat, c in baseline.items():
        lo, hi = wilson(c['high'], c['n'])
        headings.append(f"| {cat} | {c['n']} | {c['any']} ({c['any']/c['n']:.1%}) | "
                        f"{c['high']} ({c['high']/c['n']:.1%}) | {lo:.1%}–{hi:.1%} |")
    benign = [r for r in rows if not r['true_tampered']]
    malicious = [r for r in rows if r['true_tampered']]
    high = {r['record'] for r in entry if r['flag_high']}
    tp = sum(r['record'] in high for r in malicious)
    fp = sum(r['record'] in high for r in benign)
    headings += ['', f'At high confidence: synthetic TP={tp}, FN={len(malicious)-tp}, '
                f'FP={fp}, TN={len(benign)-fp}; high-confidence synthetic recall '
                f'{tp/len(malicious):.1%} and specificity {(len(benign)-fp)/len(benign):.1%}. '
                '**These apply only to the generated scenarios; do not quote as real-world estimates.**',
                '', '## Sensitivity to policy settings', '',
                '| Tolerance (s) | Bulk threshold | High-alert benign / 160 | High-alert altered / 480 |',
                '|---:|---:|---:|---:|']
    all_rows = []
    for tolerance in (0, 2, 5):
        for threshold in (3, 5, 10):
            _, x = evaluate(records, rows, tolerance, threshold)
            all_rows.extend(x)
            ah = sum(r['flag_high'] for r in x if r['true_tampered'])
            bh = sum(r['flag_high'] for r in x if not r['true_tampered'])
            headings.append(f'| {tolerance} | {threshold} | {bh} / 160 ({bh/160:.1%}) | '
                            f'{ah} / 480 ({ah/480:.1%}) |')
    headings += ['', '## Interpretation and limits', '',
                 '- Profile C changes only Modified; copying often preserves old Modified times. '
                 'The current rule intentionally omits it to avoid naïve false alarms.',
                 '- Profile D forward-dates Created and Modified; a relational rule designed '
                 'for backdating has no corroborating evidence to identify it.',
                 '- Profile E rewrites $SI and $FN consistently; these two attributes alone '
                 'do not provide a trusted independent reference.',
                 '- Profile F copies a common Created timestamp on 30/80 attacks, one of five moderately shared donor timestamps on another 30, and unique donor timestamps on the remaining 20. '
                 'The bulk-context downgrade suppresses many actual modified records together '
                 'with benign installer lookalikes.',
                 '- Some legitimate copying/extraction scenarios are indistinguishable from '
                 'backdating when only $SI and $FN are observed. A journal or independent '
                 'timeline would be needed to adjudicate them.',
                 '- This is a retrospective developer-created stress test; no participants, '
                 'fresh independent attackers, held-out volume, Windows host, or live tool '
                 'benchmark was involved.', '']
    (HERE/'RESULTS_CONTROLLED_TIMESTAMPS.md').write_text('\n'.join(headings), encoding='utf-8')
    with open(HERE/'controlled_timestamps.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0])); w.writeheader(); w.writerows(all_rows)
    print('\n'.join(headings))

if __name__ == '__main__': main()
