"""Capture screenshots of ByteProbe running on a demo case.

Run from the project folder, under a display (a real desktop, or Xvfb):

    xvfb-run -a -s "-screen 0 1500x950x24" python tools/capture_screenshots.py

It builds a demo evidence folder, runs a real scan through the GUI code, loads
a hash set, parses the sample $MFT (downloaded by evaluation/evaluate_mft.py)
and saves one PNG per tab to screenshots/current/. Nothing is faked: every
screenshot is the live window.
"""
import datetime
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from tkinter import messagebox, ttk

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

# Dialogs would block an unattended run.
messagebox.showinfo = lambda *a, **k: None
messagebox.showerror = lambda *a, **k: None
messagebox.showwarning = lambda *a, **k: None

from gui.app import ByteProbeApp  # noqa: E402
from core import hasher  # noqa: E402

OUT = os.path.join(ROOT, 'screenshots', 'current')
rnd = random.Random(20260930)


def build_case(base):
    for d in ('Documents', 'Downloads', 'tmp'):
        os.makedirs(os.path.join(base, d), exist_ok=True)

    def w(rel, data):
        p = os.path.join(base, rel)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    rb = lambda n: bytes(rnd.randrange(256) for _ in range(n))
    report = w('Documents/report.txt', b'Quarterly report. ' * 200)
    w('Documents/photo.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 2000)
    w('Documents/notes.txt', b'\x89PNG\r\n\x1a\n' + b'\x00' * 500)        # PNG named .txt
    w('Downloads/invoice.pdf.exe', b'MZ\x90\x00' + b'\x00' * 300)         # double extension
    w('Downloads/session_data.log', rb(50_000))                           # encrypted-looking
    w('Downloads/holiday.png', rb(8_000))                                 # random data named .png
    w('Downloads/mixed.dat', b'A' * 100_000 + rb(40_000) + b'A' * 100_000)  # packed section
    w('tmp/setup.exe', b'MZ\x90\x00' + b'\x00' * 300)
    w('tmp/payload.scr', b'')
    w('Documents/.hidden_note', b'x')
    old = w('Documents/ledger.txt', b'figures')
    t = (datetime.datetime.now() - datetime.timedelta(days=900)).timestamp()
    os.utime(old, (t, t))                                                  # Modified < Created
    nsrl = w('NSRLFile.txt',
             ('"SHA-1","MD5","CRC32","FileName"\n'
              + f'"{hasher.compute_hashes(report).sha1.upper()}","{"0" * 32}","0","report.txt"\n'
              ).encode())
    return nsrl


def snap(name):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    # scrot is more reliable than ImageMagick's `import` under Xvfb on Linux.
    # Keep a fallback when ImageMagick is the only capture utility present.
    if sys.platform.startswith('linux') and shutil.which('scrot'):
        subprocess.run(['scrot', '-o', path], check=True)
    else:
        subprocess.run(['import', '-window', 'root', path], check=True)
    print('saved', path, flush=True)


def find_notebook(widget):
    for c in widget.winfo_children():
        if isinstance(c, ttk.Notebook):
            return c
        n = find_notebook(c)
        if n:
            return n


def main():
    """The GUI updates itself from worker threads through root.after(), which
    needs the Tk main loop to be running. So the script is a generator that
    yields a delay (ms) or a condition, driven by root.after() inside mainloop().
    """
    base = tempfile.mkdtemp(prefix='byteprobe_demo_', dir=os.path.expanduser('~'))  # not under /tmp, so only the tmp/ subfolder trips the temp-directory check
    nsrl = build_case(os.path.join(base, 'case'))
    app = ByteProbeApp()
    root = app.root
    root.geometry('1400x900+0+0')
    nb = find_notebook(root)

    def script():
        yield 1000
        app._scan_dir.set(os.path.join(base, 'case'))
        app._start_scan()
        yield lambda: str(app._scan_btn['state']) == 'normal'
        print('scan finished', flush=True)
        yield 1000
        app._hashset = hasher.load_hash_database(nsrl)
        app._hashset_label.config(
            text=f'Loaded {len(app._hashset):,} hashes ({app._hashset.kind}) '
                 f'from {app._hashset.name}')
        app._run_hashset_match()
        names = ['01_file_catalogue', '02_type_check', '03_integrity_nsrl_known_good',
                 '04_covert_data', '05_event_log']
        for i, n in enumerate(names):
            nb.select(i)
            yield 800
            snap(n + '.png')

        mft = os.path.join(ROOT, 'evaluation', 'data', 'MFT')
        if os.path.exists(mft):
            app._mft_source.set(mft)
            app._start_mft_parse()
            yield lambda: str(app._mft_btn['state']) == 'normal'
            print('mft finished', flush=True)
            yield 2500
            nb.select(5)
            yield 1500
            snap('06_ntfs_mft.png')
        else:
            print('Sample $MFT missing; run python evaluation/evaluate_mft.py first.')

        for idx, n in ((6, '07_entropy_map'), (7, '08_virustotal_ready'), (8, '09_export')):
            nb.select(idx)
            yield 800
            snap(n + '.png')
        root.destroy()

    gen = script()
    deadline = time.time() + 600

    def step(cond=None):
        try:
            if cond is not None and not cond():
                if time.time() > deadline:
                    print('timeout waiting', flush=True)
                    root.destroy()
                    return
                root.after(200, lambda: step(cond))
                return
            nxt = next(gen)
        except StopIteration:
            return
        if callable(nxt):
            root.after(200, lambda: step(nxt))
        else:
            root.after(nxt, step)

    root.after(500, step)
    root.mainloop()


if __name__ == '__main__':
    main()
