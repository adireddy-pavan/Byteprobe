"""Report generation — CSV, HTML, and optional PDF (ReportLab) output."""

import csv
import sys
import datetime
import html as _html
import platform as _platform
from pathlib import Path
from typing import Optional

from .metadata import FileMetadata
from .hasher import FileHashes
from .signatures import SignatureResult
from .hidden_data import HiddenDataResult
from .timeline import TimelineEvent
from .mft import MFTRecord, TIMESTAMP_FIELDS

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer)
    from reportlab.lib.styles import getSampleStyleSheet
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

TOOL_VERSION = '1.0.0'


# ── Audit log ─────────────────────────────────────────────────────────────────

def build_audit_block_html(
    scan_start, scan_end, target, total_files, examiner, case_name
) -> str:
    duration = str(scan_end - scan_start).split('.')[0]
    rows = [
        ('Tool',          f'ByteProbe v{TOOL_VERSION}'),
        ('Python',        sys.version.split()[0]),
        ('Platform',      _platform.platform()),
        ('Examiner',      examiner),
        ('Case name',     case_name),
        ('Scan target',   target),
        ('Files scanned', str(total_files)),
        ('Scan started',  scan_start.strftime('%Y-%m-%d %H:%M:%S')),
        ('Scan ended',    scan_end.strftime('%Y-%m-%d %H:%M:%S')),
        ('Duration',      duration),
    ]
    inner = ''.join(
        f'<tr><td><b>{k}</b></td><td>{v}</td></tr>'
        for k, v in rows
    )
    return '<h2>Analysis Audit Metadata (not an acquisition chain of custody)</h2>' + f'<table>{inner}</table>'


# ── CSV ───────────────────────────────────────────────────────────────────────

def export_metadata_csv(metas: list[FileMetadata], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'Name', 'Size', 'Created', 'Modified',
                    'Accessed', 'Hidden', 'System', 'ReadOnly', 'Owner', 'Extension'])
        for m in metas:
            w.writerow([m.path, m.name, m.size,
                        m.created, m.modified, m.accessed,
                        m.is_hidden, m.is_system, m.is_readonly,
                        m.owner, m.extension])
    return out_path


def export_hashes_csv(hashes: list[FileHashes], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'MD5', 'SHA1', 'SHA256', 'Size'])
        for h in hashes:
            w.writerow([h.path, h.md5, h.sha1, h.sha256, h.size])
    return out_path


def export_signatures_csv(sigs: list[SignatureResult], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'DeclaredExt', 'DetectedExts', 'MagicHex', 'Mismatch', 'Note'])
        for s in sigs:
            w.writerow([s.path, s.declared_ext, '|'.join(s.detected_exts),
                        s.magic_hex, s.mismatch, s.note])
    return out_path


def export_timeline_csv(events: list[TimelineEvent], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Timestamp', 'EventKind', 'Path', 'Size', 'Extension', 'Hidden', 'System'])
        for e in events:
            w.writerow([e.timestamp, e.kind, e.path, e.size, e.extension,
                        e.is_hidden, e.is_system])
    return out_path


def export_entropy_csv(entropy_results, out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'Entropy', 'HighEntropy', 'Note'])
        for e in entropy_results:
            w.writerow([e.path, e.entropy, e.is_high_entropy, e.note])
    return out_path


def _mft_ts(ts, name: str) -> str:
    dt = ts.as_datetime(name) if ts else None
    return dt.isoformat() if dt else ''


def export_mft_csv(records: list[MFTRecord], out_path: str) -> str:
    """Every parsed MFT record with both $SI and $FN timestamp sets (UTC)."""
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Record', 'Sequence', 'InUse', 'Directory', 'Path']
                   + [f'SI_{n}' for n in TIMESTAMP_FIELDS]
                   + [f'FN_{n}' for n in TIMESTAMP_FIELDS]
                   + ['ADS'])
        for r in records:
            fn_ts = r.fn.timestamps if r.fn else None
            w.writerow([r.record_number, r.sequence, r.in_use, r.is_directory, r.path]
                       + [_mft_ts(r.si, n) for n in TIMESTAMP_FIELDS]
                       + [_mft_ts(fn_ts, n) for n in TIMESTAMP_FIELDS]
                       + ['|'.join(f'{a.name}({a.size}B)' for a in r.ads)])
    return out_path


def _si_fn_summary(anomalies) -> str:
    if anomalies is None:
        return 'not analysed'
    high = sum(1 for a in anomalies if a['confidence'] == 'high')
    return f'{high} / {len(anomalies)}'


def export_si_fn_csv(anomalies: list[dict], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Record', 'Path', 'InUse', 'Confidence', 'SI_Created', 'FN_Created',
                    'SI_Modified', 'FN_Modified', 'Findings'])
        for a in anomalies:
            w.writerow([a['record'], a['path'], a['in_use'], a['confidence'], a['si_created'],
                        a['fn_created'], a['si_modified'], a['fn_modified'], a['note']])
    return out_path


# ── HTML ──────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ByteProbe Report — {title}</title>
<style>
  body {{ font-family: Consolas, monospace; font-size: 13px; background: #0f1117; color: #e2e8f0; margin: 40px; }}
  h1   {{ color: #c084fc; border-bottom: 1px solid #c084fc; padding-bottom: 8px; }}
  h2   {{ color: #a78bfa; margin-top: 32px; }}
  .meta {{ color: #94a3b8; font-size: 11px; margin-bottom: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th    {{ background: #2d1b69; color: #c084fc; padding: 8px 12px; text-align: left; }}
  td    {{ padding: 6px 12px; border-bottom: 1px solid #1e293b; }}
  tr:nth-child(even) {{ background: #1e1e2e; }}
  .warn  {{ color: #f87171; font-weight: bold; }}
  .ok    {{ color: #4ade80; }}
  .badge {{ background: #f87171; color: white; border-radius: 4px;
            padding: 1px 6px; font-size: 10px; margin-left: 6px; }}
</style>
</head>
<body>
<h1>ByteProbe — Windows File Analysis Tool for Digital Forensics</h1>
<div class="meta">
  Generated: {generated}<br>
  Examiner:  {examiner}<br>
  Case:      {case}<br>
  Target:    {target}
</div>
{body}
</body>
</html>
"""

_TABLE_TMPL = "<h2>{heading}</h2><table><tr>{headers}</tr>{rows}</table>"


def _th(cols: list[str]) -> str:
    return ''.join(f'<th>{c}</th>' for c in cols)


def _tr(cells: list[str]) -> str:
    return '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'


def _fmt(val) -> str:
    if val is True:
        return '<span class="warn">YES</span>'
    if val is False:
        return '<span class="ok">no</span>'
    # File names in evidence are attacker-controlled: never emit them raw
    return _html.escape(str(val)) if val is not None else ''


def export_html_report(
    out_path: str,
    metas: list[FileMetadata],
    hashes: list[FileHashes],
    sigs: list[SignatureResult],
    hidden: list[HiddenDataResult],
    events: list[TimelineEvent],
    examiner: str = "Unknown",
    case_name: str = "Untitled",
    target_path: str = "",
    scan_start=None,
    scan_end=None,
    si_fn_anomalies: Optional[list[dict]] = None,
    mft_source: str = "",
) -> str:
    examiner    = _html.escape(str(examiner))
    case_name   = _html.escape(str(case_name))
    target_path = _html.escape(str(target_path))

    sections: list[str] = []

    if scan_start and scan_end:
        sections.append(build_audit_block_html(
            scan_start, scan_end, target_path, len(metas), examiner, case_name))

    # Summary
    mismatches  = [s for s in sigs if s.mismatch]
    suspicious  = [h for h in hidden if h.is_suspicious]
    total_files = len(metas)
    sections.append(
        f"<h2>Summary</h2>"
        f"<p>Total files scanned: <strong>{total_files}</strong><br>"
        f"Signature mismatches: <strong class=\"warn\">{len(mismatches)}</strong><br>"
        f"Suspicious items (ADS / flags): <strong class=\"warn\">{len(suspicious)}</strong><br>"
        f"Timeline events: <strong>{len(events)}</strong><br>"
        f"$SI/$FN timestamp anomalies (high confidence / all): <strong class=\"warn\">"
        f"{_si_fn_summary(si_fn_anomalies)}</strong></p>"
    )

    # NTFS $SI vs $FN (timestomping)
    if si_fn_anomalies:
        cap = 500
        ordered = sorted(si_fn_anomalies, key=lambda a: a['confidence'] != 'high')
        rows = ''.join(_tr([_fmt(a['record']), _fmt(a['path']), _fmt(a['confidence']),
                            _fmt(a['si_created']), _fmt(a['fn_created']), _fmt(a['note'])])
                       for a in ordered[:cap])
        sections.append(_TABLE_TMPL.format(
            heading=(f"NTFS $STANDARD_INFORMATION vs $FILE_NAME anomalies "
                     f"({len(si_fn_anomalies)}) — source: {_html.escape(mft_source)}"),
            headers=_th(['MFT Record', 'Path', 'Confidence', '$SI Created', '$FN Created',
                         'Findings']),
            rows=rows,
        ))

    # Metadata table
    cap = 500
    if len(metas) > cap:
        warn = (f' <span class="warn">WARNING: showing {cap} of {len(metas)}'
                f' — export CSV for complete evidence</span>')
    else:
        warn = ''
    rows = ''.join(_tr([_fmt(m.path), _fmt(m.size), _fmt(m.created),
                        _fmt(m.modified), _fmt(m.is_hidden), _fmt(m.is_system),
                        _fmt(m.owner)])
                   for m in metas[:cap])
    sections.append(_TABLE_TMPL.format(
        heading=f"File Metadata ({min(len(metas), cap)} of {len(metas)} files){warn}",
        headers=_th(['Path', 'Size', 'Created', 'Modified', 'Hidden', 'System', 'Owner']),
        rows=rows,
    ))

    # Signature mismatches
    if mismatches:
        rows = ''.join(_tr([_fmt(s.path), _fmt(s.declared_ext),
                            _fmt(', '.join(s.detected_exts)), _fmt(s.note)])
                       for s in mismatches)
        sections.append(_TABLE_TMPL.format(
            heading=f"Signature Mismatches ({len(mismatches)})",
            headers=_th(['Path', 'Declared', 'Detected', 'Note']),
            rows=rows,
        ))

    # Hashes
    cap = 200
    if len(hashes) > cap:
        warn = (f' <span class="warn">WARNING: showing {cap} of {len(hashes)}'
                f' — export CSV for complete evidence</span>')
    else:
        warn = ''
    rows = ''.join(_tr([_fmt(h.path), _fmt(h.md5), _fmt(h.sha256)])
                   for h in hashes[:cap])
    sections.append(_TABLE_TMPL.format(
        heading=f"Cryptographic Hashes ({min(len(hashes), cap)} of {len(hashes)}){warn}",
        headers=_th(['Path', 'MD5', 'SHA-256']),
        rows=rows,
    ))

    # Suspicious items
    if suspicious:
        rows_html = []
        for r in suspicious:
            flags = '; '.join(r.suspicion_flags)
            ads   = '; '.join(f"{a.stream_name} ({a.size}B)" for a in r.ads_streams)
            rows_html.append(_tr([_fmt(r.meta.path), _fmt(flags or '—'), _fmt(ads or '—')]))
        sections.append(_TABLE_TMPL.format(
            heading=f"Suspicious Items ({len(suspicious)})",
            headers=_th(['Path', 'Flags', 'ADS Streams']),
            rows=''.join(rows_html),
        ))

    # Timeline
    cap = 1000
    if len(events) > cap:
        warn = (f' <span class="warn">WARNING: showing {cap} of {len(events)}'
                f' — export CSV for complete evidence</span>')
    else:
        warn = ''
    rows = ''.join(_tr([_fmt(e.timestamp), _fmt(e.kind), _fmt(e.path)])
                   for e in events[:cap])
    sections.append(_TABLE_TMPL.format(
        heading=f"Timeline ({min(len(events), cap)} of {len(events)} events){warn}",
        headers=_th(['Timestamp', 'Event', 'Path']),
        rows=rows,
    ))

    html = _HTML_TEMPLATE.format(
        title=case_name,
        generated=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        examiner=examiner,
        case=case_name,
        target=target_path,
        body='\n'.join(sections),
    )

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return out_path


# ── PDF (ReportLab optional) ──────────────────────────────────────────────────

def export_pdf_report(
    out_path: str,
    metas: list[FileMetadata],
    hashes: list[FileHashes],
    sigs: list[SignatureResult],
    hidden: list[HiddenDataResult] = None,
    events: list[TimelineEvent] = None,
    examiner: str = "Unknown",
    case_name: str = "Untitled",
    target_path: str = "",
    scan_start=None,
    scan_end=None,
    si_fn_anomalies: Optional[list[dict]] = None,
    mft_source: str = "",
) -> str:
    if not HAS_REPORTLAB:
        raise RuntimeError("ReportLab is not installed. Run: pip install reportlab")

    hidden = hidden or []
    events = events or []

    styles = getSampleStyleSheet()
    doc    = SimpleDocTemplate(out_path, pagesize=A4)
    story  = []

    story.append(Paragraph("ByteProbe — Windows File Analysis Tool for Digital Forensics", styles['Title']))
    story.append(Spacer(1, 12))
    meta_text = (f"Case: {case_name} | Examiner: {examiner} | "
                 f"Target: {target_path} | "
                 f"Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 20))

    # Summary table
    mismatches = [s for s in sigs if s.mismatch]
    suspicious = [h for h in hidden if h.is_suspicious]
    story.append(Paragraph("Summary", styles['Heading2']))
    summary_data = [
        ['Metric', 'Value'],
        ['Total files scanned', str(len(metas))],
        ['Signature mismatches', str(len(mismatches))],
        ['Suspicious hidden items', str(len(suspicious))],
        ['Hash records', str(len(hashes))],
        ['Timeline events', str(len(events))],
        ['$SI/$FN anomalies (high / all)', _si_fn_summary(si_fn_anomalies)],
    ]
    t = Table(summary_data, colWidths=[200, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.purple),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Mismatch table
    if mismatches:
        story.append(Paragraph(f"Signature Mismatches ({len(mismatches)})", styles['Heading2']))
        data = [['Path', 'Declared', 'Detected', 'Note']]
        for s in mismatches[:100]:
            data.append([
                Paragraph(s.path[-60:], styles['Normal']),
                s.declared_ext,
                ', '.join(s.detected_exts),
                Paragraph(s.note, styles['Normal']),
            ])
        t = Table(data, colWidths=[200, 60, 80, 160])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

    # NTFS $SI vs $FN section
    if si_fn_anomalies:
        story.append(Paragraph(
            f"NTFS $SI vs $FN Anomalies ({len(si_fn_anomalies)})", styles['Heading2']))
        data = [['Record', 'Path', '$SI Created', '$FN Created', 'Findings']]
        for a in sorted(si_fn_anomalies, key=lambda a: a['confidence'] != 'high')[:200]:
            data.append([
                str(a['record']),
                Paragraph(_html.escape(a['path'][-60:]), styles['Normal']),
                a['si_created'][:19],
                a['fn_created'][:19],
                Paragraph(_html.escape(a['note']), styles['Normal']),
            ])
        t = Table(data, colWidths=[40, 150, 85, 85, 140])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

    # Hidden data section
    if suspicious:
        story.append(Paragraph(f"Suspicious Items ({len(suspicious)})", styles['Heading2']))
        data = [['Path', 'Suspicion Flags', 'ADS Streams']]
        for r in suspicious[:200]:
            flags = '; '.join(r.suspicion_flags)
            ads   = '; '.join(f"{a.stream_name}({a.size}B)" for a in r.ads_streams)
            data.append([
                Paragraph(r.meta.path[-60:], styles['Normal']),
                Paragraph(flags or '—', styles['Normal']),
                Paragraph(ads or '—', styles['Normal']),
            ])
        t = Table(data, colWidths=[160, 180, 160])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

    # Timeline section
    if events:
        story.append(Paragraph(
            f"Timeline (first 500 of {len(events)} events)", styles['Heading2']))
        data = [['Timestamp', 'Event', 'Path']]
        for e in events[:500]:
            data.append([
                e.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                e.kind,
                Paragraph(e.path[-70:], styles['Normal']),
            ])
        t = Table(data, colWidths=[120, 60, 320])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.purple),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)

    doc.build(story)
    return out_path
