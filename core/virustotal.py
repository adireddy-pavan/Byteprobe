"""VirusTotal API v3 — check file hashes against known malicious samples."""

import urllib.request
import urllib.error
import json
import time
from dataclasses import dataclass

VT_URL    = "https://www.virustotal.com/api/v3/files/{}"
VT_GUI    = "https://www.virustotal.com/gui/file/{}"
RATE_WAIT = 16  # free tier: 4 requests/min → 1 per 15s, 16s to stay safe


@dataclass
class VTResult:
    path:          str
    sha256:        str
    malicious:     int
    suspicious:    int
    undetected:    int
    total_engines: int
    verdict:       str   # 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'
    permalink:     str
    error:         str


def check_hash(sha256: str, api_key: str) -> dict:
    req = urllib.request.Request(
        VT_URL.format(sha256),
        headers={"x-apikey": api_key}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data  = json.loads(resp.read().decode())
            stats = data['data']['attributes']['last_analysis_stats']
            mal   = stats.get('malicious',   0)
            sus   = stats.get('suspicious',  0)
            und   = stats.get('undetected',  0)
            total = sum(stats.values())
            verdict = 'malicious' if mal > 0 else 'suspicious' if sus > 0 else 'clean'
            return {
                'malicious':   mal,
                'suspicious':  sus,
                'undetected':  und,
                'total':       total,
                'verdict':     verdict,
                'permalink':   VT_GUI.format(sha256),
                'error':       '',
            }
    except urllib.error.HTTPError as e:
        msgs = {
            404: 'Not in VirusTotal database',
            401: 'Invalid API key',
            429: 'Rate limit reached — wait and retry',
        }
        return {'verdict': 'unknown' if e.code == 404 else 'error',
                'error': msgs.get(e.code, f'HTTP {e.code}'),
                'malicious': 0, 'suspicious': 0, 'undetected': 0,
                'total': 0, 'permalink': ''}
    except Exception as exc:
        return {'verdict': 'error', 'error': str(exc),
                'malicious': 0, 'suspicious': 0, 'undetected': 0,
                'total': 0, 'permalink': ''}


def check_all(hashes, api_key: str, progress_cb=None,
              cancel_flag=None) -> list[VTResult]:
    results = []
    total   = len(hashes)

    for i, fh in enumerate(hashes):
        if cancel_flag and cancel_flag.is_set():
            break

        if progress_cb:
            progress_cb(i + 1, total, fh.path)

        r = check_hash(fh.sha256, api_key)
        results.append(VTResult(
            path          = fh.path,
            sha256        = fh.sha256,
            malicious     = r['malicious'],
            suspicious    = r['suspicious'],
            undetected    = r['undetected'],
            total_engines = r['total'],
            verdict       = r['verdict'],
            permalink     = r['permalink'],
            error         = r['error'],
        ))

        # Respect free-tier rate limit between requests
        if i < total - 1:
            for _ in range(RATE_WAIT):
                if cancel_flag and cancel_flag.is_set():
                    break
                time.sleep(1)

    return results
