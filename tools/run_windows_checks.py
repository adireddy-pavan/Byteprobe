"""Execute the non-invasive part of ByteProbe's Windows verification protocol.

Run ONLY on a Windows test VM, from the ByteProbe root:
    python tools/run_windows_checks.py --output windows_evidence

This tool creates disposable test files within a TemporaryDirectory, verifies
W1-W4 and W7 where feasible, and retains JSON results. Windows volume parsing
(W5) and real timestomping (W6) require manually documented examiner actions;
it NEVER accesses a raw disk, requests elevated rights, or tampers with user data.
Any FAIL or NOT_TESTED must be retained in the report, not overridden.
"""
import argparse
import datetime
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def run(destination):
    if platform.system() != 'Windows':
        raise RuntimeError('Windows verification is Windows-only; no Windows results produced.')
    from core import metadata, hidden_data, reporter
    import ctypes

    dest = Path(destination).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    results = {
        'run_started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'platform': platform.platform(), 'python': sys.version,
        'pywin32_available': metadata.HAS_WIN32,
        'reportlab_available': reporter.HAS_REPORTLAB,
        'checks': {}, 'methodology': 'Automated disposable-file checks only; W5/W6 manual'
    }

    def check(name, status, detail):
        results['checks'][name] = {'status': status, 'detail': detail}

    try:
        r = subprocess.run([sys.executable, '-m', 'unittest', 'tests.test_gui_smoke', '-v'],
                           cwd=str(ROOT), capture_output=True, text=True, timeout=120)
        transcript = (r.stdout + '\n' + r.stderr)
        (dest/'W1_gui_tests.txt').write_text(transcript, encoding='utf-8')
        good = r.returncode == 0 and 'Ran 5 tests' in transcript and 'skipped=' not in transcript.lower()
        check('W1', 'PASS' if good else 'FAIL',
              'Real GUI smoke test transcript saved; ' + transcript[-350:])
    except Exception as exc:
        check('W1', 'FAIL', repr(exc))

    with tempfile.TemporaryDirectory(prefix='byteprobe_windows_validation_') as temp:
        folder = Path(temp)
        file = folder/'probe.txt'
        file.write_text('ByteProbe disposable NTFS test file', encoding='utf-8')
        meta = metadata.extract_metadata(str(file))
        check('W2', 'PASS' if (metadata.HAS_WIN32 and meta.owner not in ('Unknown', 'N/A (Windows only)')) else 'FAIL',
              f'Owner (may contain test-user identity, stored locally): {meta.owner}')

        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        f = k32.SetFileAttributesW
        f.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        f.restype = ctypes.c_int
        hidden = folder/'probe_hidden.txt'
        hidden.write_text('temporary verification file', encoding='utf-8')
        try:
            if not f(str(hidden), 0x02 | 0x04 | 0x20):
                raise OSError(ctypes.get_last_error(), 'SetFileAttributesW failed')
            hm = metadata.extract_metadata(str(hidden))
            check('W3', 'PASS' if hm.is_hidden and hm.is_system else 'FAIL',
                  f'Flags: hidden={hm.is_hidden} system={hm.is_system}; attr=0x{hm.attributes:x}')
        except Exception as exc:
            check('W3', 'FAIL', repr(exc))
        finally:
            f(str(hidden), 0x80)

        try:
            with open(str(file)+':byteprobe_test', 'w', encoding='utf-8') as out:
                out.write('disposable ADS content')
            ads = hidden_data.enumerate_ads(str(file))
            names = [x.stream_name for x in ads]
            check('W4', 'PASS' if any('byteprobe_test' in x for x in names) else 'FAIL',
                  f'Observed ADS stream names: {names}')
        except Exception as exc:
            check('W4', 'FAIL', repr(exc))

        try:
            now = datetime.datetime.now()
            reporter.export_metadata_csv([meta], str(dest/'W7_metadata.csv'))
            reporter.export_html_report(str(dest/'W7_report.html'), [meta], [], [], [], [],
                  examiner='Automated Windows test', case_name='Disposable test only',
                  target_path=str(folder), scan_start=now, scan_end=datetime.datetime.now())
            if reporter.HAS_REPORTLAB:
                reporter.export_pdf_report(str(dest/'W7_report.pdf'), [meta], [], [], [], [],
                  examiner='Automated Windows test', case_name='Disposable test only',
                  target_path=str(folder))
            generated = [str(p.name) for p in dest.glob('W7_*')]
            good = all((dest/f).stat().st_size > 0 for f in generated)
            good = good and 'W7_metadata.csv' in generated and 'W7_report.html' in generated
            if not reporter.HAS_REPORTLAB:
                check('W7', 'PARTIAL', f'CSV/HTML created; PDF not tested. {generated}')
            else:
                check('W7', 'PASS' if good and 'W7_report.pdf' in generated else 'FAIL',
                      f'Files: {generated}, size>0={good}')
        except Exception as exc:
            check('W7', 'FAIL', repr(exc))

    check('W5', 'NOT_TESTED', 'Administrator live-volume analysis and separately extracted $MFT comparison must be performed and documented manually.')
    check('W6', 'NOT_TESTED', 'Real Windows timestomping profile must be run on dedicated disposable test volume, with before/after MFT evidence.')
    results['run_ended_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = json.dumps(results, indent=2)
    (dest/'windows_validation.json').write_text(payload, encoding='utf-8')
    print(payload)
    return 0 if all(v['status']=='PASS' for k,v in results['checks'].items() if k not in ('W5','W6')) else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', default='windows_evidence', help='Directory to retain actual Windows verification results')
    args = ap.parse_args()
    try: sys.exit(run(args.output))
    except RuntimeError as exc:
        print(f'NOT TESTED: {exc}', file=sys.stderr)
        sys.exit(3)

if __name__ == '__main__': main()
