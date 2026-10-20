"""Opt-in real-Windows NTFS lab for W5 and W6 on ONE disposable file.

This is deliberately NOT run by CI or on the examiner's own evidence.
Run from an elevated PowerShell prompt on a Windows 10/11 NTFS system:

  python tools/run_windows_w5_w6_lab.py --confirm-disposable-test --output windows_evidence/W5_W6

The script creates just one temporary file, and changes ONLY that file's
Created timestamp through SetFileTime. The parser opens the volume read-only.
It never formats, mounts, acquires, or changes a disk. If conditions are not
satisfied, it refuses and records the reason; it never invents PASS results.
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import sys
import tempfile
import traceback
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def preflight(system=None, consent=False):
    system = system or platform.system()
    if not consent:
        raise RuntimeError('Explicit --confirm-disposable-test is required.')
    if system != 'Windows':
        raise RuntimeError('Windows-only procedure; no NTFS result is possible on this host.')


def _is_elevated():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _volume_fs_type(drive):
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    getinfo = kernel.GetVolumeInformationW
    getinfo.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    getinfo.restype = wintypes.BOOL
    fsname = ctypes.create_unicode_buffer(128)
    root = drive + '\\'
    if not getinfo(root, None, 0, None, None, None, fsname, len(fsname)):
        raise OSError(ctypes.get_last_error(), 'GetVolumeInformationW failed')
    return fsname.value


def _set_created_utc(path, newdate):
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    class FILETIME(ctypes.Structure):
        _fields_ = [('dwLowDateTime', wintypes.DWORD), ('dwHighDateTime', wintypes.DWORD)]
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    settime = kernel.SetFileTime
    settime.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILETIME),
                        ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
    settime.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    # NTFS FILETIME is 100 ns ticks since 1601-01-01 UTC.
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    delta = newdate - epoch
    ticks = ((delta.days * 86400 + delta.seconds) * 10_000_000
             + delta.microseconds * 10)
    ft = FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)
    handle = create(str(path), 0x100, 0x1 | 0x2 | 0x4, None, 3, 0, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), 'CreateFileW for temporary timestamp test')
    try:
        if not settime(handle, ctypes.byref(ft), None, None):
            raise OSError(ctypes.get_last_error(), 'SetFileTime failed')
    finally:
        close(handle)


def _matching_record(records, path):
    # MFT paths are rooted at the volume, not prefixed by a drive letter.
    drive, rest = os.path.splitdrive(str(path))
    target = '\\' + rest.lstrip('\\/').replace('/', '\\').casefold()
    candidates = [r for r in records if r.in_use and r.path.casefold() == target]
    if len(candidates) != 1:
        raise RuntimeError(f'Expected one MFT entry matching test path; found {len(candidates)}. '
                           'Possible path aliases or unsupported volume. No pass recorded.')
    return candidates[0]


def _summary(record):
    si, fn = record.si, record.fn.timestamps if record.fn else None
    return {
        'record_number': record.record_number,
        'sequence': record.sequence,
        'resolved_path': record.path,
        'fixup_ok': record.fixup_ok,
        'in_use': record.in_use,
        'si_created_utc': si.as_datetime('created').isoformat() if si and si.as_datetime('created') else None,
        'fn_created_utc': fn.as_datetime('created').isoformat() if fn and fn.as_datetime('created') else None,
        'si_raw_created_ticks': si.created if si else None,
        'fn_raw_created_ticks': fn.created if fn else None,
    }


def run(output, test_root=None):
    from core.mft import parse_mft
    from core.timeline import check_si_fn
    directory = Path(test_root).resolve() if test_root else Path(tempfile.gettempdir()).resolve()
    drive = directory.drive
    if len(drive) != 2 or drive[1] != ':' or not directory.is_dir():
        raise RuntimeError('Test root must be an existing local Windows drive directory.')
    if _volume_fs_type(drive).upper() != 'NTFS':
        raise RuntimeError(f'{drive} is not NTFS; cannot perform this lab.')
    if not _is_elevated():
        raise RuntimeError('An elevated Windows PowerShell session is required to read the live NTFS volume.')
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {
        'platform': platform.platform(), 'python': sys.version,
        'volume': drive, 'filesystem': 'NTFS',
        'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'W5': {'status': 'NOT_TESTED'}, 'W6': {'status': 'NOT_TESTED'},
        'method': 'one disposable file; SetFileTime Created only; live $MFT opened rb',
        'source_code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    try:
        with tempfile.TemporaryDirectory(prefix='byteprobe_mft_lab_', dir=directory) as td:
            specimen = Path(td) / ('probe_' + uuid.uuid4().hex + '.txt')
            specimen.write_text('Disposable ByteProbe timestamp specimen; not case evidence.\n', encoding='utf-8')
            source = '\\\\.\\' + drive
            before_records = parse_mft(source, include_deleted=False)
            before = _matching_record(before_records, specimen)
            before_info = _summary(before)
            result['W5'] = {'status': 'PASS' if before.fixup_ok and before.si and before.fn else 'FAIL',
                            'live_volume_source': source,
                            'parsed_base_records': len(before_records),
                            'specimen_before': before_info}
            if result['W5']['status'] != 'PASS':
                raise RuntimeError('Live MFT record lacks valid fixup or timestamps.')
            requested = dt.datetime(2019, 1, 1, 9, 0, 0, tzinfo=dt.timezone.utc)
            _set_created_utc(specimen, requested)
            actual_created = dt.datetime.fromtimestamp(specimen.stat().st_ctime, tz=dt.timezone.utc)
            after_records = parse_mft(source, include_deleted=False)
            after = _matching_record(after_records, specimen)
            findings = check_si_fn(after)
            changed = after.si.created < before.si.created - 2 * 10_000_000
            unchanged_fn = after.fn.timestamps.created == before.fn.timestamps.created
            observed = (changed and unchanged_fn and bool(findings)
                        and abs((actual_created - requested).total_seconds()) < 2)
            result['W6'] = {
                'status': 'PASS' if observed else 'FAIL',
                'requested_si_created_utc': requested.isoformat(),
                'observed_file_created_utc': actual_created.isoformat(),
                'specimen_after': _summary(after),
                'findings': findings,
                'same_record_number_and_sequence':
                    (before.record_number, before.sequence) == (after.record_number, after.sequence),
                'changed_si_created': changed, 'unchanged_fn_created': unchanged_fn,
            }
    except Exception as exc:
        result['exception'] = repr(exc)
        result['traceback'] = traceback.format_exc(limit=6)
        # Existing passed observation stays passed; unexecuted/failed later step does not.
        if result['W6']['status'] == 'NOT_TESTED' and result['W5']['status'] == 'PASS':
            result['W6']['status'] = 'FAIL'
    result['ended_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
    (out/'W5_W6_real_windows_results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['W5']['status'] == result['W6']['status'] == 'PASS' else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--confirm-disposable-test', action='store_true',
                    help='Confirm that one disposable file may be created and timestamp-modified')
    ap.add_argument('--output', default='windows_evidence/W5_W6')
    ap.add_argument('--test-root', default=None,
                    help='Existing LOCAL NTFS directory for a temporary specimen; defaults to %%TEMP%%')
    args = ap.parse_args()
    try:
        preflight(consent=args.confirm_disposable_test)
        sys.exit(run(args.output, args.test_root))
    except RuntimeError as exc:
        print('NOT TESTED: ' + str(exc), file=sys.stderr)
        sys.exit(3)


if __name__ == '__main__':
    main()
