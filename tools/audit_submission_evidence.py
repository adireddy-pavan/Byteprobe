"""Conservative evidence inventory for a ByteProbe assessment submission.

This checks the presence and internal consistency of evidence FILES, not the
truthfulness of their origin. It deliberately does not declare a dissertation
ready or a student entitled to any mark. No blank check is silently passed.

Usage:
 python tools/audit_submission_evidence.py --evidence evidence_external --out evidence_audit.json

Expected files, provided externally after genuine execution:
  windows/windows_validation.json (W1...W7)
  parser/summary.json          (real same-evidence MFTECmd comparison)
  github/remote_commit.txt     (full 40-character SHA + remote URL)
  screencast/screencast.mp4    (authentic final run; human checks required)
  submission/declaration.pdf  (actually signed, locally supplied)
  supervision/evidence_index.txt (actual contemporaneous records or candid absence)

NEVER fabricate these files merely to pass an audit; document unavailable items.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import re
from pathlib import Path

EXPECTED_CHECKS = tuple(f'W{i}' for i in range(1, 8))

def audit(root: Path) -> dict:
    root = Path(root)
    result = {'audit_generated_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'source_directory': str(root.resolve()), 'items': {},
              'IMPORTANT': 'File inventory only; human provenance and content review required.'}
    items = result['items']
    win = root/'windows/windows_validation.json'
    if win.exists():
        try:
            data = json.loads(win.read_text(encoding='utf-8'))
            checks = data.get('checks', {})
            st = {k: checks.get(k, {}).get('status', 'MISSING') for k in EXPECTED_CHECKS}
            platform = data.get('platform', '')
            complete = 'Windows' in platform and all(x == 'PASS' for x in st.values())
            items['windows'] = {'status': 'RECORDED_PASS' if complete else 'INCOMPLETE',
                                'platform': platform, 'checks': st,
                                'note': 'W5/W6 require separately performed real NTFS checks; a human must review the evidence.'}
        except Exception as e:
            items['windows'] = {'status': 'INVALID', 'error': str(e)}
    else:
        items['windows'] = {'status': 'NOT_PROVIDED'}
    b = root/'parser/summary.json'
    if b.exists():
        try:
            data = json.loads(b.read_text(encoding='utf-8'))
            required = ('byteprobe_input_sha256','reference_csv_sha256','common_record_keys')
            present = all(data.get(k) for k in required)
            items['independent_parser'] = {
                'status': 'REPORTED_REQUIRES_PROVENANCE_REVIEW' if present else 'INVALID',
                'common_record_keys': data.get('common_record_keys'),
                'note': 'Summary cannot authenticate source image, external tool, or execution by itself.'}
        except Exception as e:
            items['independent_parser'] = {'status':'INVALID','error':str(e)}
    else:
        items['independent_parser'] = {'status': 'NOT_PROVIDED'}
    g = root/'github/remote_commit.txt'
    if g.exists():
        txt = g.read_text(encoding='utf-8')
        sha = re.search(r'\b[0-9a-fA-F]{40}\b',txt)
        url = re.search(r'https://github\.com/[^\s]+', txt)
        items['github'] = {'status':'PRESENT_REMOTE_CHECK_REQUIRED' if sha and url else 'INVALID',
                           'note':'Local text cannot prove the commit exists on GitHub.'}
    else:
        items['github'] = {'status':'NOT_PROVIDED'}
    for key, fn in [('screencast','screencast/screencast.mp4'),
                    ('declaration','submission/declaration.pdf'),
                    ('supervision','supervision/evidence_index.txt')]:
        p=root/fn
        items[key]={'status':'PRESENT_REQUIRES_HUMAN_REVIEW' if p.is_file() and p.stat().st_size>0 else 'NOT_PROVIDED',
                    'note':{'screencast':'Must be the final genuine tool recording on a stated platform.',
                            'declaration':'Student signature and template compliance require human review.',
                            'supervision':'Authenticity of historical records cannot be established from filenames.'}[key]}
    result['fully_verified'] = False
    result['reason'] = 'Human and external provenance checks are mandatory even when all files are present.'
    return result

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',default='evidence_external')
    p.add_argument('--out',default='evidence_audit.json')
    args=p.parse_args()
    output=audit(Path(args.evidence))
    Path(args.out).write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(output,indent=2))
