"""Windows handoff runner: record real evidence under PROJECT/verification_results.

This is a convenience wrapper around the existing ByteProbe validation utilities.
It does not claim any Windows validation until it actually runs on Windows.
No results are fabricated. The separate lab stage requires an explicitly nominated
non-system NTFS disk intended solely for disposable testing.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import traceback
import zipfile

PROJECT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT / 'verification_results'


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def ensure_windows():
    if platform.system() != 'Windows':
        raise RuntimeError('Windows-only action. No Windows verification result was created.')


def run_logged(argv, name, timeout=900):
    dest = OUTPUT / 'logs'
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / (name + '.txt')
    with path.open('w', encoding='utf-8') as out:
        out.write('UTC started: ' + utcnow() + '\n')
        out.write('Command arguments: ' + repr([str(s) for s in argv]) + '\n')
        out.write('Working directory: ' + str(PROJECT) + '\n\n')
        out.flush()
        try:
            result = subprocess.run([str(x) for x in argv], cwd=PROJECT,
                                    stdout=out, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
            code = result.returncode
        except Exception as e:
            code = 254
            out.write('\nEXCEPTION: ' + repr(e) + '\n')
        out.write('\nUTC finished: ' + utcnow() + '\nExit code: ' + str(code) + '\n')
    print(f'{name}: exit {code}, log = {path.relative_to(PROJECT)}', flush=True)
    return code


def read_json(path):
    if Path(path).is_file():
        return json.loads(Path(path).read_text(encoding='utf-8'))
    return None


def write_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def consolidate_windows():
    basic = read_json(OUTPUT / 'windows' / 'basic' / 'windows_validation.json')
    lab = read_json(OUTPUT / 'windows' / 'lab' / 'W5_W6_real_windows_results.json')
    if basic is None and lab is None:
        return
    data = {
        'platform': (basic or lab).get('platform', platform.platform()),
        'compiled_utc': utcnow(),
        'checks': dict(basic.get('checks', {})) if basic else {},
        'evidence_sources': {
            'basic': 'windows/basic/windows_validation.json' if basic else None,
            'lab': 'windows/lab/W5_W6_real_windows_results.json' if lab else None,
        },
        'IMPORTANT': 'Derived from actual stage logs; does not authenticate raw data or instrument accuracy.',
    }
    if lab:
        if basic and basic.get('platform') != lab.get('platform'):
            raise RuntimeError('Host platform details differ between stages: investigate before merging evidence.')
        for key in ('W5','W6'):
            data['checks'][key] = lab.get(key, {'status': 'NOT_TESTED'})
    for i in range(1, 8):
        data['checks'].setdefault(f'W{i}', {'status': 'NOT_TESTED'})
    write_json(OUTPUT / 'windows' / 'windows_validation.json', data)


def basic():
    ensure_windows()
    (OUTPUT / 'windows' / 'basic').mkdir(parents=True, exist_ok=True)
    vers = {}
    for name in ('pywin32', 'reportlab'):
        try:
            vers[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            vers[name] = 'not installed'
    write_json(OUTPUT / 'windows' / 'environment.json', {
        'captured_utc': utcnow(), 'platform': platform.platform(),
        'python': sys.version, 'python_executable': sys.executable,
        'dependency_versions': vers, 'project_root': str(PROJECT),
        'NOTE': 'Paths and test-user identities may be personal; keep evidence private.',
    })
    code_suite = run_logged([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.', '-v'],
                            'windows_full_unit_suite', timeout=300)
    code_checks = run_logged([sys.executable, str(PROJECT / 'tools/run_windows_checks.py'),
                              '--output', str(OUTPUT / 'windows/basic')],
                             'windows_basic_W1_W4_W7', timeout=300)
    try:
        consolidate_windows()
    except Exception as e:
        (OUTPUT/'logs/merge_error.txt').write_text(str(e),encoding='utf-8')
        raise
    suite = (OUTPUT/'logs/windows_full_unit_suite.txt').read_text(encoding='utf-8',errors='replace')
    m = re.search(r'Ran (\d+) tests? in ', suite)
    gui = 'skipped=' not in suite and code_suite == 0
    write_json(OUTPUT/'windows/basic_stage.json', {
        'performed_utc': utcnow(), 'unit_test_exit_code': code_suite,
        'discovered_test_count': int(m.group(1)) if m else None,
        'zero_skipped_unit_tests': gui,
        'basic_windows_check_exit_code': code_checks,
        'status': 'PASS' if code_suite == code_checks == 0 and gui else 'FAIL_OR_INCOMPLETE',
        'interpretation': 'W1-W4/W7 + tests only. W5/W6 require an independent advanced stage.',
    })
    return 0 if code_suite == code_checks == 0 and gui else 2


def lab(test_root, ack):
    ensure_windows()
    if not ack:
        raise RuntimeError('Lab requires --acknowledge-disposable-vhd.')
    if not test_root:
        raise RuntimeError('Lab requires --test-root on a dedicated non-system NTFS VHD volume.')
    p = Path(test_root).resolve()
    drive = p.drive.upper()
    system_drive = os.environ.get('SystemDrive', 'C:').upper()
    if not drive or drive == system_drive:
        raise RuntimeError(f'LAB REFUSED: {p} is the system drive ({system_drive}) or is not a drive-letter path. Use a dedicated, disposable attached NTFS VHDX.')
    if not p.is_dir():
        raise RuntimeError(f'Test root does not exist: {p}. Create a folder inside the isolated NTFS VHDX first.')
    target = OUTPUT / 'windows' / 'lab'
    target.mkdir(parents=True, exist_ok=True)
    code = run_logged([sys.executable, str(PROJECT/'tools/run_windows_w5_w6_lab.py'),
                       '--confirm-disposable-test', '--test-root', str(p), '--output', str(target)],
                      'windows_lab_W5_W6', timeout=1500)
    consolidate_windows()
    write_json(OUTPUT/'windows/lab_stage.json', {
        'performed_utc': utcnow(), 'test_root': str(p),
        'advanced_lab_exit_code': code,
        'status': 'PASS' if code == 0 else 'FAIL_OR_INCOMPLETE',
        'NOTE': 'W6 tests only creation-time manipulation on one disposable specimen. No broader detector validation is implied.'
    })
    return 0 if code == 0 else 2


def benchmark(mft_path, tool_path):
    ensure_windows()
    if not mft_path or not tool_path:
        raise RuntimeError('Benchmark requires both --mft-file and --mftecmd-exe.')
    mf = Path(mft_path).resolve()
    ex = Path(tool_path).resolve()
    if not mf.is_file() or not ex.is_file():
        raise RuntimeError('Extracted $MFT and MFTECmd.exe must be existing, ordinary files. No live volume path is accepted.')
    if mf.stat().st_size < 1024:
        raise RuntimeError('Extracted $MFT is suspiciously small. Check the independent evidence source.')
    d = OUTPUT / 'parser'
    d.mkdir(parents=True, exist_ok=True)
    csv_path = d / 'reference.csv'
    provenance = {
        'performed_utc': utcnow(), 'tool_path': str(ex),
        'tool_sha256': digest(ex), 'input_path': str(mf), 'input_sha256': digest(mf),
        'input_bytes': mf.stat().st_size,
        'reference_tool_name': 'MFTECmd',
        'dataset_is_independent': 'UNVERIFIED_REQUIRES_SOURCE_RECORD',
        'NOTE': 'The same raw bytes must be processed by MFTECmd and ByteProbe. Do not call this an independent second dataset without source verification.',
    }
    write_json(d/'provenance.json', provenance)
    run_logged([str(ex), '--help'], 'mftecmd_help_version',timeout=60)
    code_ref = run_logged([str(ex), '-f', str(mf), '--csv', str(d), '--csvf', csv_path.name, '--at'],
                           'mftecmd_reference_export',timeout=1200)
    if code_ref or not csv_path.is_file() or csv_path.stat().st_size == 0:
        write_json(d/'benchmark_stage.json',{'status':'FAIL_OR_INCOMPLETE','mftecmd_exit_code':code_ref,'reference_csv_created':csv_path.is_file()})
        return 2
    provenance['reference_csv_sha256'] = digest(csv_path)
    write_json(d/'provenance.json', provenance)
    code_cmp = run_logged([sys.executable, str(PROJECT/'evaluation/compare_mftecmd.py'),
                           str(mf), str(csv_path), '--out', str(d)],
                          'byteprobe_mftecmd_comparison',timeout=1200)
    summary=read_json(d/'summary.json')
    write_json(d/'benchmark_stage.json', {
        'performed_utc':utcnow(), 'reference_tool_exit_code':code_ref,
        'comparison_exit_code':code_cmp,
        'common_record_keys': (summary or {}).get('common_record_keys'),
        'status':'RESULTS_GENERATED_REVIEW_REQUIRED' if code_cmp==0 and summary else 'FAIL_OR_INCOMPLETE',
        'NOTE':'A generated comparison can contain disagreements and excluded fields. Review before grade claims.'
    })
    return 0 if code_cmp==0 and summary else 2


def manifest():
    items=[]
    for p in sorted(OUTPUT.rglob('*')):
        if p.is_file() and p.name != 'MANIFEST_SHA256.txt':
            items.append(f'{digest(p)}  {p.relative_to(PROJECT).as_posix()}')
    (OUTPUT/'MANIFEST_SHA256.txt').write_text('\n'.join(items)+'\n',encoding='utf-8')


def bundle():
    OUTPUT.mkdir(exist_ok=True)
    manifest()
    target=PROJECT/'ByteProbe_Verification_Results.zip'
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=5) as z:
        for p in sorted(OUTPUT.rglob('*')):
            if p.is_file():
                z.write(p,p.relative_to(PROJECT).as_posix())
    print('RESULTS DIRECTORY:', OUTPUT)
    print('SHAREABLE RESULTS ZIP:', target)
    print('WARNING: Contents may include file paths and usernames. Inspect before sending externally.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=('basic','lab','benchmark','bundle'))
    p.add_argument('--test-root',help='Existing folder on dedicated non-system NTFS VHDX (lab)')
    p.add_argument('--acknowledge-disposable-vhd', action='store_true')
    p.add_argument('--mft-file',help='Extracted authentic NTFS $MFT file (benchmark)')
    p.add_argument('--mftecmd-exe',help='Absolute path to official MFTECmd.exe (benchmark)')
    args=p.parse_args()
    try:
        code= {'basic':lambda:basic(),
               'lab':lambda:lab(args.test_root,args.acknowledge_disposable_vhd),
               'benchmark':lambda:benchmark(args.mft_file,args.mftecmd_exe),
               'bundle':lambda:0}[args.stage]()
    except Exception as e:
        OUTPUT.mkdir(parents=True,exist_ok=True)
        error={'at_utc':utcnow(),'stage':args.stage, 'status':'NOT_COMPLETED',
               'error':str(e),'traceback':traceback.format_exc(limit=5)}
        write_json(OUTPUT/f'{args.stage}_error.json',error)
        print('ERROR:', e, file=sys.stderr)
        code=3
    try:
        bundle()
    except Exception as e:
        print('Unable to package results:', e,file=sys.stderr)
        code=max(code,3)
    return code

if __name__=='__main__':
    sys.exit(main())
