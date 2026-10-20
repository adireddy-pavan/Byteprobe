"""Evaluate ByteProbe's signature and entropy detectors on a labelled corpus.

The corpus is generated (seed 20260930) so the result is reproducible. Ground
truth is known because each file is built on purpose. The signature detector is
compared with libmagic's `file` command, an industry-standard reference.

    python evaluation/evaluate_detectors.py

This is a SYNTHETIC corpus built by the same author as the detectors, so
100% scores show the logic works on the cases it was designed for, not that it
is perfect on real data. It measures the logic of each detector, not how
they behave on a real disk; say so in the report.
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import io
import zipfile
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core import signatures, entropy  # noqa: E402

rnd = random.Random(20260930)


def rand_bytes(n):
    return bytes(rnd.randrange(256) for _ in range(n))


def text(n):
    words = ['report', 'invoice', 'case', 'evidence', 'file', 'hash', 'user', 'log']
    return (' '.join(rnd.choice(words) for _ in range(n // 6))).encode()[:n]


PNG = b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + b'\x00' * 17
PE = b'MZ\x90\x00' + b'\x00' * 56 + struct.pack('<I', 64) + b'PE\x00\x00' + b'\x00' * 200
PDF = b'%PDF-1.4\n' + text(2000)
def _make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('a.bin', rand_bytes(6000))   # incompressible payload
    return buf.getvalue()


ZIP = _make_zip()


def build(d):
    """Return list of (path, is_wrong_extension, is_high_entropy_content)."""
    items = []

    def add(name, data, wrong_ext, high):
        p = os.path.join(d, name)
        with open(p, 'wb') as f:
            f.write(data)
        items.append((p, wrong_ext, high))

    # honest files
    for i in range(30):
        add(f'doc{i}.txt', text(5000), False, False)
        add(f'img{i}.png', PNG + text(3000), False, False)
        add(f'prog{i}.exe', PE + text(4000), False, False)
        add(f'paper{i}.pdf', PDF, False, False)
        add(f'arch{i}.zip', ZIP, False, True)   # compressed -> legitimately high entropy
    # extension disguised
    for i in range(30):
        add(f'holiday{i}.jpg', PE + text(4000), True, False)      # exe named .jpg
        add(f'notes{i}.txt', PDF, True, False)                     # pdf named .txt
        add(f'photo{i}.png', rand_bytes(8000), True, True)         # random data named .png
    # encrypted / packed content
    for i in range(30):
        add(f'blob{i}.dat', rand_bytes(20000), False, True)
        add(f'packed{i}.exe', PE + rand_bytes(20000), False, True)
    return items


def file_cmd_says_mismatch(path):
    """libmagic: mismatch when the detected type is a different well-known type."""
    out = subprocess.run(['file', '--brief', '--mime-type', path],
                         capture_output=True, text=True).stdout.strip()
    ext = os.path.splitext(path)[1].lower()
    expect = {'.txt': ('text/',), '.png': ('image/png',), '.jpg': ('image/jpeg',),
              '.exe': ('application/x-dosexec',
                       'application/vnd.microsoft.portable-executable'),
              '.pdf': ('application/pdf',), '.zip': ('application/zip',)}.get(ext)
    return expect is not None and not out.startswith(expect)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r


def main():
    d = tempfile.mkdtemp()
    try:
        items = build(d)
        n_wrong = sum(1 for _, w, _ in items if w)
        n_high = sum(1 for _, _, h in items if h)
        print(f'Corpus: {len(items)} files, {n_wrong} wrong-extension, {n_high} high-entropy content\n')

        have_file = shutil.which('file') is not None
        rows = []
        tp = fp = fn = 0
        ftp = ffp = ffn = 0
        for p, wrong, _ in items:
            pred = signatures.analyze_signature(p).mismatch
            tp += pred and wrong; fp += pred and not wrong; fn += (not pred) and wrong
            if have_file:
                fpred = file_cmd_says_mismatch(p)
                ftp += fpred and wrong; ffp += fpred and not wrong; ffn += (not fpred) and wrong
        print('| Signature check | Precision | Recall |\n|---|---|---|')
        p, r = prf(tp, fp, fn)
        print(f'| ByteProbe | {p:.1%} | {r:.1%} |')
        if have_file:
            p, r = prf(ftp, ffp, ffn)
            print(f'| libmagic `file` | {p:.1%} | {r:.1%} |')

        tp = fp = fn = 0
        for p, _, high in items:
            pred = entropy.compute_entropy(p).is_high_entropy
            tp += pred and high; fp += pred and not high; fn += (not pred) and high
        p, r = prf(tp, fp, fn)
        print('\n| Entropy check (> 7.2) | Precision | Recall |\n|---|---|---|')
        print(f'| ByteProbe | {p:.1%} | {r:.1%} |')
        print('\nNote: ZIP archives are compressed, so they are high-entropy by design. '
              'Entropy alone cannot separate legitimate compression from encryption or '
              'packing, which is why ByteProbe combines it with signature and extension checks.')
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    main()
