"""ByteProbe v1.0 — Tkinter GUI."""

import os
import sys
import platform
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import metadata as md_mod
from core import signatures as sig_mod
from core import hasher as hash_mod
from core import hidden_data as hid_mod
from core import timeline as tl_mod
from core import reporter
from core import entropy as ent_mod
from core import virustotal as vt_mod
from core import mft as mft_mod

# ── Palette ───────────────────────────────────────────────────────────────────
BG     = '#0d0d1a'
BG2    = '#1a0f2e'
BG3    = '#110c1f'
ACCENT = '#b06aff'
WARN   = '#ff5555'
OK     = '#50fa7b'
FG     = '#f8f8f2'
FG2    = '#6272a4'
SEP    = '#3d2b6e'
FONT   = ('Courier New', 10)
FONT_B = ('Courier New', 10, 'bold')
FONT_S = ('Courier New', 9)

MFT_ROW_CAP = 50_000   # Treeview becomes unusable beyond this; export CSV for all


class ToggleBtn(tk.Button):
    """Circle-style toggle that syncs with a BooleanVar."""
    def __init__(self, parent, text, variable, command=None, **kw):
        self._var      = variable
        self._label    = text
        self._callback = command
        super().__init__(parent, command=self._toggle,
                         relief='flat', bd=0, padx=10, pady=4,
                         cursor='hand2', font=FONT, **kw)
        self._var.trace_add('write', lambda *_: self._refresh())
        self._refresh()

    def _toggle(self):
        self._var.set(not self._var.get())
        if self._callback:
            self._callback()

    def _refresh(self):
        on = self._var.get()
        self.config(
            text=f'  ●  {self._label}  ' if on else f'  ○  {self._label}  ',
            fg=ACCENT if on else FG2,
            bg=BG2   if on else BG,
            activeforeground=ACCENT,
            activebackground=BG2,
        )


def _apply_theme(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=BG, foreground=FG, font=FONT,
                    fieldbackground=BG2, bordercolor=SEP)
    style.configure('TNotebook',      background=BG3, tabmargins=[2, 4, 0, 0])
    style.configure('TNotebook.Tab',  background=BG2, foreground=FG2,
                    padding=[12, 4], font=FONT_B)
    style.map('TNotebook.Tab',
              background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('Treeview',         background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=20, font=FONT)
    style.configure('Treeview.Heading', background=BG3, foreground=ACCENT, font=FONT_B)
    style.map('Treeview', background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('TButton', background=BG2, foreground=ACCENT, font=FONT_B,
                    padding=6, borderwidth=1, relief='flat')
    style.map('TButton', background=[('active', ACCENT)],
                         foreground=[('active', BG)])
    style.configure('TLabel',       background=BG,  foreground=FG,  font=FONT)
    style.configure('TFrame',       background=BG)
    style.configure('TEntry',       fieldbackground=BG2, foreground=FG, font=FONT,
                    insertcolor=ACCENT)
    style.configure('TCheckbutton', background=BG, foreground=FG, font=FONT)
    style.configure('TProgressbar', troughcolor=BG2, background=ACCENT)
    style.configure('TScrollbar',   background=BG2, troughcolor=BG3)
    style.configure('TRadiobutton', background=BG, foreground=FG, font=FONT)


# ── Reusable table widget ─────────────────────────────────────────────────────

class TableView(ttk.Frame):
    def __init__(self, parent, columns: list[tuple[str, int]], **kw):
        super().__init__(parent, **kw)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        col_ids = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=col_ids, show='headings', selectmode='browse')
        vsb = ttk.Scrollbar(self, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        for col_id, width in columns:
            self.tree.heading(col_id, text=col_id,
                              command=lambda c=col_id: self._sort(c, False))
            self.tree.column(col_id, width=width, minwidth=40, anchor='w')

        self.tree.tag_configure('warn',   foreground=WARN)
        self.tree.tag_configure('ok',     foreground=OK)
        self.tree.tag_configure('orange', foreground='#ffb86c')

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def insert(self, values: list, tag: str = ''):
        self.tree.insert('', 'end', values=values, tags=(tag,) if tag else ())

    def row_count(self) -> int:
        return len(self.tree.get_children())

    def _sort(self, col: str, reverse: bool):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            data.sort(
                key=lambda x: float(x[0]) if x[0].replace('.', '', 1).lstrip('-').isdigit()
                else x[0].lower(),
                reverse=reverse)
        except Exception:
            data.sort(reverse=reverse)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)
        self.tree.heading(col, command=lambda: self._sort(col, not reverse))


# ── Main application ──────────────────────────────────────────────────────────

class ByteProbeApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ByteProbe v1.0 — Digital Forensics Toolkit")
        self.root.geometry("1400x900")
        self.root.minsize(1024, 680)
        self.root.configure(bg=BG)
        _apply_theme(self.root)

        # Scan state
        self._metas:     list[md_mod.FileMetadata]      = []
        self._hashes:    list[hash_mod.FileHashes]       = []
        self._sigs:      list[sig_mod.SignatureResult]   = []
        self._hidden:    list[hid_mod.HiddenDataResult]  = []
        self._events:    list[tl_mod.TimelineEvent]      = []
        self._entropy:   list[ent_mod.EntropyResult]     = []
        self._anomalies: list[dict]                      = []
        self._hashset:    set[str]                       = set()
        self._vt_results: list[vt_mod.VTResult]         = []
        self._mft_records: list[mft_mod.MFTRecord]      = []
        self._mft_index:   mft_mod.MFTIndex | None      = None
        self._si_fn:       list[dict]                   = []
        self._meta_mft:    dict[str, mft_mod.MFTRecord] = {}
        self._mft_source_used = ''
        self._mft_cancel = threading.Event()
        self._scan_start = None
        self._scan_end   = None
        self._cancel_flag = threading.Event()

        self._scan_dir    = tk.StringVar()
        self._recursive   = tk.BooleanVar(value=True)
        self._run_hashes  = tk.BooleanVar(value=True)
        self._run_sigs    = tk.BooleanVar(value=True)
        self._run_hidden  = tk.BooleanVar(value=True)
        self._run_entropy = tk.BooleanVar(value=True)

        self._mft_source       = tk.StringVar()
        self._mft_offset       = tk.StringVar()
        self._mft_show         = tk.StringVar(value='flagged')
        self._mft_incl_deleted = tk.BooleanVar(value=True)

        self._status_var = tk.StringVar(
            value="Ready — select a target directory and press RUN")

        self._build_ui()

    # ── UI layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_menubar()
        self._build_header()
        self._build_controls()
        self._build_stats_bar()
        self._build_notebook()
        self._build_statusbar()

    def _build_menubar(self):
        mb = tk.Menu(self.root, bg=BG3, fg=FG,
                     activebackground=ACCENT, activeforeground=BG,
                     relief='flat', bd=0)

        file_m = tk.Menu(mb, tearoff=0, bg=BG2, fg=FG,
                         activebackground=ACCENT, activeforeground=BG)
        file_m.add_command(label="Load Hash Set…", command=self._load_hashset)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self.root.quit)
        mb.add_cascade(label="File", menu=file_m)

        scan_m = tk.Menu(mb, tearoff=0, bg=BG2, fg=FG,
                         activebackground=ACCENT, activeforeground=BG)
        scan_m.add_command(label="▶  Start Scan", command=self._start_scan)
        scan_m.add_command(label="■  Stop Scan",  command=self._stop_scan)
        scan_m.add_separator()
        scan_m.add_command(label="Clear Results", command=self._reset)
        mb.add_cascade(label="Scan", menu=scan_m)

        export_m = tk.Menu(mb, tearoff=0, bg=BG2, fg=FG,
                           activebackground=ACCENT, activeforeground=BG)
        export_m.add_command(label="Export CSV Bundle",  command=self._export_csv)
        export_m.add_command(label="Export HTML Report", command=self._export_html)
        export_m.add_command(label="Export PDF Report",  command=self._export_pdf)
        mb.add_cascade(label="Export", menu=export_m)

        help_m = tk.Menu(mb, tearoff=0, bg=BG2, fg=FG,
                         activebackground=ACCENT, activeforeground=BG)
        help_m.add_command(label="About ByteProbe", command=self._show_about)
        mb.add_cascade(label="Help", menu=help_m)

        self.root.config(menu=mb)

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG3)
        hdr.pack(fill='x')
        tk.Frame(hdr, bg=SEP, height=1).pack(fill='x')
        inner = tk.Frame(hdr, bg=BG3)
        inner.pack(fill='x', padx=16, pady=8)
        tk.Label(inner, text="[ BYTEPROBE ]",
                 font=('Courier New', 18, 'bold'), fg=ACCENT, bg=BG3).pack(side='left')
        tk.Label(inner, text="   forensic file analysis toolkit",
                 font=FONT, fg=FG2, bg=BG3).pack(side='left', pady=2)
        if platform.system() != 'Windows':
            tk.Label(inner,
                     text="  ⚠  non-Windows: 'created' = inode-change time",
                     fg=WARN, bg=BG3, font=FONT_S).pack(side='right')
        tk.Frame(hdr, bg=SEP, height=1).pack(fill='x')

    def _build_controls(self):
        ctrl = tk.Frame(self.root, bg=BG, pady=6)
        ctrl.pack(fill='x', padx=16)

        row = tk.Frame(ctrl, bg=BG)
        row.pack(fill='x')

        tk.Label(row, text="TARGET:", fg=FG2, bg=BG, font=FONT_B).pack(side='left')
        ttk.Entry(row, textvariable=self._scan_dir, width=58).pack(side='left', padx=6)
        ttk.Button(row, text="Browse…", command=self._browse).pack(side='left')

        tk.Frame(row, bg=SEP, width=1).pack(side='left', fill='y', padx=10)

        for text, var in [("Recursive",  self._recursive),
                           ("Hashing",    self._run_hashes),
                           ("Signatures", self._run_sigs),
                           ("Hidden",     self._run_hidden),
                           ("Entropy",    self._run_entropy)]:
            ToggleBtn(row, text=text, variable=var).pack(side='left', padx=2)

        prow = tk.Frame(ctrl, bg=BG)
        prow.pack(fill='x', pady=(4, 0))

        self._scan_btn = ttk.Button(prow, text="▶  RUN",  command=self._start_scan)
        self._scan_btn.pack(side='left', padx=(0, 4))
        self._stop_btn = ttk.Button(prow, text="■  STOP", command=self._stop_scan,
                                    state='disabled')
        self._stop_btn.pack(side='left', padx=2)
        ttk.Button(prow, text="CLR", command=self._reset).pack(side='left', padx=4)

        tk.Frame(prow, bg=SEP, width=1).pack(side='left', fill='y', padx=10)

        self._progress = ttk.Progressbar(prow, mode='indeterminate', length=500)
        self._progress.pack(side='left', fill='x', expand=True)

    def _build_stats_bar(self):
        sb = tk.Frame(self.root, bg=BG, pady=4)
        sb.pack(fill='x', padx=16)

        self._stat_vars = {
            'files':      tk.StringVar(value='—'),
            'mismatches': tk.StringVar(value='—'),
            'suspicious': tk.StringVar(value='—'),
            'anomalies':  tk.StringVar(value='—'),
            'si_fn':      tk.StringVar(value='—'),
        }
        cards = [
            ('files',      'files scanned', ACCENT),
            ('mismatches', 'sig mismatches', WARN),
            ('suspicious', 'suspicious',     WARN),
            ('anomalies',  'ts anomalies',   '#ffb86c'),
            ('si_fn',      '$SI/$FN (high)', WARN),
        ]
        for key, label, color in cards:
            card = tk.Frame(sb, bg=BG2, padx=16, pady=4)
            card.pack(side='left', padx=(0, 8))
            tk.Label(card, textvariable=self._stat_vars[key],
                     font=('Courier New', 18, 'bold'), fg=color, bg=BG2).pack()
            tk.Label(card, text=label, font=FONT_S, fg=FG2, bg=BG2).pack()

    def _build_notebook(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=16, pady=(4, 0))

        self._tab_metadata = self._make_metadata_tab(nb)
        self._tab_sigs     = self._make_sigs_tab(nb)
        self._tab_hashes   = self._make_hashes_tab(nb)
        self._tab_hidden   = self._make_hidden_tab(nb)
        self._tab_timeline = self._make_timeline_tab(nb)
        self._tab_mft      = self._make_mft_tab(nb)
        self._tab_entropy  = self._make_entropy_tab(nb)
        self._tab_report   = self._make_report_tab(nb)
        self._tab_vt       = self._make_vt_tab(nb)

        nb.add(self._tab_metadata, text="  File Catalogue  ")
        nb.add(self._tab_sigs,     text="  Type Check  ")
        nb.add(self._tab_hashes,   text="  Integrity  ")
        nb.add(self._tab_hidden,   text="  Covert Data  ")
        nb.add(self._tab_timeline, text="  Event Log  ")
        nb.add(self._tab_mft,      text="  NTFS $MFT  ")
        nb.add(self._tab_entropy,  text="  Entropy Map  ")
        nb.add(self._tab_vt,       text="  VirusTotal  ")
        nb.add(self._tab_report,   text="  Export  ")

    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=BG3)
        sb.pack(fill='x', side='bottom')
        tk.Frame(sb, bg=SEP, height=1).pack(fill='x')
        inner = tk.Frame(sb, bg=BG3)
        inner.pack(fill='x', padx=12, pady=3)
        tk.Label(inner, textvariable=self._status_var,
                 fg=FG2, bg=BG3, font=FONT_S, anchor='w').pack(side='left')
        tk.Label(inner, text="ByteProbe v1.0",
                 fg=SEP, bg=BG3, font=FONT_S).pack(side='right')

    # ── Tab builders ──────────────────────────────────────────────────────────

    def _make_metadata_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        search_row = ttk.Frame(frame)
        search_row.grid(row=0, column=0, sticky='ew', padx=4, pady=4)
        ttk.Label(search_row, text="Filter:").pack(side='left')
        self._meta_search = tk.StringVar()
        ttk.Entry(search_row, textvariable=self._meta_search, width=40).pack(side='left', padx=4)
        ttk.Button(search_row, text="Search",
                   command=self._filter_metadata).pack(side='left', padx=2)
        ttk.Button(search_row, text="Clear Filter",
                   command=self._clear_meta_filter).pack(side='left', padx=2)
        self._meta_filter_label = ttk.Label(search_row, text="")
        self._meta_filter_label.pack(side='left', padx=8)

        cols = [('Path', 300), ('Name', 150), ('Size', 80),
                ('Created', 140), ('Modified', 140), ('Hidden', 55),
                ('System', 55), ('ReadOnly', 65), ('Owner', 120), ('Ext', 55), ('Risk', 55)]
        self._meta_table = TableView(frame, cols)
        self._meta_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_sigs_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('Declared', 70), ('Detected', 130),
                ('MagicHex', 200), ('Mismatch', 65), ('Note', 300)]
        self._sig_table = TableView(frame, cols)
        self._sig_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_hashes_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=0, column=0, sticky='ew', padx=4, pady=4)
        ttk.Button(btn_row, text='Load Hash Set (NSRL / known-bad)',
                   command=self._load_hashset).pack(side='left', padx=4)
        self._hashset_label = ttk.Label(btn_row, text='No hash set loaded')
        self._hashset_label.pack(side='left', padx=8)

        cols = [('Path', 300), ('MD5', 240), ('SHA-1', 290),
                ('SHA-256', 430), ('Size', 80), ('In HashSet?', 80)]
        self._hash_table = TableView(frame, cols)
        self._hash_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_hidden_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        if platform.system() != 'Windows':
            tk.Label(frame,
                     text='Windows ADS API unavailable on this platform — ADS are'
                          ' read from a parsed $MFT instead (NTFS $MFT tab).',
                     fg=WARN, bg=BG, font=FONT_B, anchor='w'
                     ).grid(row=0, column=0, sticky='ew', padx=8, pady=4)

        cols = [('Path', 300), ('ADS Streams', 180), ('Suspicion Flags', 400)]
        self._hidden_table = TableView(frame, cols)
        self._hidden_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_timeline_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(0, weight=1)

        filt_row = ttk.Frame(frame)
        filt_row.grid(row=0, column=0, sticky='ew', padx=4, pady=4)
        ttk.Label(filt_row, text="Show:").pack(side='left')
        self._tl_kind = tk.StringVar(value='all')
        for kind in ('all', 'created', 'modified', 'accessed'):
            ttk.Radiobutton(filt_row, text=kind, variable=self._tl_kind,
                            value=kind, command=self._refresh_timeline).pack(side='left', padx=4)
        self._tl_incl_accessed = tk.BooleanVar(value=False)
        ToggleBtn(filt_row, text="Include accessed events",
                  variable=self._tl_incl_accessed,
                  command=self._rebuild_timeline).pack(side='left', padx=12)

        cols = [('Timestamp', 155), ('Event', 75), ('Path', 400),
                ('Size', 80), ('Ext', 55), ('Hidden', 55)]
        self._tl_table = TableView(frame, cols)
        self._tl_table.grid(row=1, column=0, sticky='nsew')

        tk.Label(frame,
                 text='OS Timestamp Anomalies (Modified before Created — low confidence;'
                      ' see NTFS $MFT tab for $SI/$FN analysis)',
                 fg=WARN, bg=BG, font=FONT_B, anchor='w'
                 ).grid(row=2, column=0, sticky='ew', padx=8, pady=(8, 2))
        anomaly_cols = [('Path', 350), ('Created', 155), ('Modified', 155),
                        ('Delta', 100), ('Note', 280)]
        self._anomaly_table = TableView(frame, anomaly_cols)
        self._anomaly_table.grid(row=3, column=0, sticky='nsew')
        return frame

    def _make_mft_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=3)
        frame.rowconfigure(5, weight=2)

        src = tk.Frame(frame, bg=BG, pady=6)
        src.grid(row=0, column=0, sticky='ew', padx=8)
        tk.Label(src, text="SOURCE:", fg=FG2, bg=BG, font=FONT_B).pack(side='left')
        ttk.Entry(src, textvariable=self._mft_source, width=50).pack(side='left', padx=6)
        ttk.Button(src, text="Browse $MFT / image…",
                   command=self._browse_mft).pack(side='left')
        if platform.system() == 'Windows':
            ttk.Button(src, text="Use target's volume",
                       command=self._use_live_volume).pack(side='left', padx=4)
        tk.Label(src, text="Offset (bytes):", fg=FG2, bg=BG,
                 font=FONT_S).pack(side='left', padx=(10, 2))
        ttk.Entry(src, textvariable=self._mft_offset, width=12).pack(side='left')
        self._mft_btn = ttk.Button(src, text="▶  Parse $MFT",
                                   command=self._start_mft_parse)
        self._mft_btn.pack(side='left', padx=(10, 2))
        self._mft_stop_btn = ttk.Button(src, text="■  Stop",
                                        command=self._stop_mft_parse, state='disabled')
        self._mft_stop_btn.pack(side='left', padx=2)

        tk.Label(frame,
                 text="Accepts an extracted $MFT, a raw NTFS volume or disk image"
                      " (dd/.raw/.img, MBR or GPT), or \\\\.\\C: on Windows"
                      " (Administrator). Offset is only needed if auto-detection fails."
                      " Timestamps are UTC with full 100 ns precision.",
                 fg=FG2, bg=BG, font=FONT_S, anchor='w'
                 ).grid(row=1, column=0, sticky='ew', padx=8)

        filt = ttk.Frame(frame)
        filt.grid(row=2, column=0, sticky='ew', padx=4, pady=4)
        ttk.Label(filt, text="Show:").pack(side='left')
        for value, text in (('flagged', 'high-confidence $SI/$FN + ADS'),
                            ('all', f'all records (first {MFT_ROW_CAP:,})')):
            ttk.Radiobutton(filt, text=text, variable=self._mft_show, value=value,
                            command=self._refresh_mft_table).pack(side='left', padx=4)
        ToggleBtn(filt, text="Include deleted records", variable=self._mft_incl_deleted,
                  command=self._refresh_mft_table).pack(side='left', padx=12)
        self._mft_summary = ttk.Label(filt, text="")
        self._mft_summary.pack(side='left', padx=8)

        ts_w = 205
        cols = ([('Record', 65), ('Path', 340), ('In Use', 55)]
                + [(f'$SI {n}', ts_w) for n in ('Created', 'Modified', 'MFT-Changed', 'Accessed')]
                + [(f'$FN {n}', ts_w) for n in ('Created', 'Modified', 'MFT-Changed', 'Accessed')]
                + [('ADS', 220)])
        self._mft_table = TableView(frame, cols)
        self._mft_table.grid(row=3, column=0, sticky='nsew')

        tk.Label(frame,
                 text='$STANDARD_INFORMATION vs $FILE_NAME — timestomping indicators',
                 fg=WARN, bg=BG, font=FONT_B, anchor='w'
                 ).grid(row=4, column=0, sticky='ew', padx=8, pady=(8, 2))
        si_fn_cols = [('Record', 65), ('Path', 340), ('In Use', 55), ('Confidence', 80),
                      ('$SI Created', 185), ('$FN Created', 185), ('Findings', 600)]
        self._si_fn_table = TableView(frame, si_fn_cols)
        self._si_fn_table.grid(row=5, column=0, sticky='nsew')
        return frame

    def _make_entropy_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('Entropy Score', 90), ('High Entropy?', 70), ('Note', 250)]
        self._entropy_table = TableView(frame, cols)
        self._entropy_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_vt_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=1)

        # API key row
        key_row = tk.Frame(frame, bg=BG, pady=6)
        key_row.grid(row=0, column=0, sticky='ew', padx=8)
        tk.Label(key_row, text="VirusTotal API Key:", fg=FG2, bg=BG,
                 font=FONT_B).pack(side='left')
        self._vt_api_key = tk.StringVar()
        ttk.Entry(key_row, textvariable=self._vt_api_key,
                  width=60, show='*').pack(side='left', padx=8)
        self._vt_btn = ttk.Button(key_row, text="▶  Check on VirusTotal",
                                  command=self._start_vt_check)
        self._vt_btn.pack(side='left', padx=4)
        self._vt_stop_btn = ttk.Button(key_row, text="■  Stop",
                                       command=self._stop_vt_check,
                                       state='disabled')
        self._vt_stop_btn.pack(side='left', padx=2)

        # Info row
        info_row = tk.Frame(frame, bg=BG)
        info_row.grid(row=1, column=0, sticky='ew', padx=8, pady=(0, 4))
        tk.Label(info_row,
                 text="⚠  Free tier: 4 requests/min — large scans will take time."
                      "  Get a free API key at virustotal.com",
                 fg='#ffb86c', bg=BG, font=FONT_S).pack(side='left')
        self._vt_progress_label = tk.Label(info_row, text="", fg=FG2,
                                           bg=BG, font=FONT_S)
        self._vt_progress_label.pack(side='right', padx=8)

        # Results table
        cols = [('Path', 300), ('SHA-256', 350), ('Malicious', 75),
                ('Suspicious', 75), ('Total Engines', 90), ('Verdict', 90),
                ('VT Link', 250)]
        self._vt_table = TableView(frame, cols)
        self._vt_table.grid(row=2, column=0, sticky='nsew', padx=4, pady=4)
        return frame

    def _make_report_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.columnconfigure(1, weight=1)

        fields = [
            ("Examiner name:", 'examiner', "Lead Analyst"),
            ("Case name:",     'case',     "Evidence-001"),
        ]
        self._report_vars: dict[str, tk.StringVar] = {}
        for row, (label, key, default) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=12, pady=6)
            var = tk.StringVar(value=default)
            self._report_vars[key] = var
            ttk.Entry(frame, textvariable=var, width=40).grid(
                row=row, column=1, sticky='ew', padx=12, pady=6)

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=len(fields), column=0, columnspan=2, pady=16, padx=12, sticky='w')
        ttk.Button(btn_row, text="Export CSV bundle",  command=self._export_csv).pack(side='left', padx=4)
        ttk.Button(btn_row, text="Export HTML report", command=self._export_html).pack(side='left', padx=4)
        ttk.Button(btn_row, text="Export PDF report",  command=self._export_pdf).pack(side='left', padx=4)

        self._report_log = tk.Text(frame, height=12, bg=BG2, fg=FG, font=FONT,
                                   state='disabled', wrap='word')
        self._report_log.tag_configure('ok',   foreground=OK)
        self._report_log.tag_configure('err',  foreground=WARN)
        self._report_log.tag_configure('info', foreground=FG)
        self._report_log.grid(row=len(fields)+1, column=0, columnspan=2,
                               sticky='nsew', padx=12, pady=4)
        frame.rowconfigure(len(fields)+1, weight=1)
        return frame

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        d = filedialog.askdirectory(title="Select target directory")
        if d:
            self._scan_dir.set(d)

    def _start_scan(self):
        target = self._scan_dir.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter or browse to a target directory.")
            return
        if not os.path.isdir(target):
            messagebox.showerror("Error", f"Directory not found:\n{target}")
            return
        self._cancel_flag.clear()
        self._scan_btn.config(state='disabled')
        self._stop_btn.config(state='normal')
        self._progress.start(10)
        self._set_status("Scanning…")
        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()

    def _stop_scan(self):
        self._cancel_flag.set()
        self._set_status("Cancelling — finishing current file…")
        self._stop_btn.config(state='disabled')

    def _run_scan(self, target: str):
        self._scan_start = datetime.datetime.now()
        total = 0
        try:
            # 1. Metadata
            self._metas = []
            self._set_status("Extracting metadata…")
            count = [0]

            def _meta_cb(m):
                count[0] += 1
                self._set_status(f"Metadata: {count[0]} files — {m.name}")

            self._metas = md_mod.scan_directory(
                target, recursive=self._recursive.get(), progress_cb=_meta_cb)
            total = len(self._metas)
            self._populate_metadata()
            self._update_stats()

            if self._cancel_flag.is_set():
                self._set_status(f"Cancelled after metadata — {total} files indexed.")
                return

            # 2. Signatures
            self._sigs = []
            if self._run_sigs.get():
                done = [0]
                def _sig_cb(p):
                    done[0] += 1
                    self._set_status(
                        f"Signatures: {done[0]} / {total} — {os.path.basename(p)}")
                self._sigs = sig_mod.analyze_all(
                    [m.path for m in self._metas], progress_cb=_sig_cb)
                self._populate_sigs()
                self._update_stats()

            if self._cancel_flag.is_set():
                self._set_status(f"Cancelled after signatures — {total} files.")
                return

            # 3. Hashes
            self._hashes = []
            if self._run_hashes.get():
                done = [0]
                def _hash_cb(p):
                    done[0] += 1
                    self._set_status(
                        f"Hashes: {done[0]} / {total} — {os.path.basename(p)}")
                self._hashes = hash_mod.hash_all(
                    [m.path for m in self._metas], progress_cb=_hash_cb)
                self._populate_hashes()

            if self._cancel_flag.is_set():
                self._set_status(f"Cancelled after hashing — {total} files.")
                return

            # 4. Hidden data
            self._hidden = []
            if self._run_hidden.get():
                done = [0]
                def _hid_cb(p):
                    done[0] += 1
                    self._set_status(
                        f"Hidden data: {done[0]} / {total} — {os.path.basename(p)}")
                self._hidden = hid_mod.analyze_all(self._metas, progress_cb=_hid_cb)
                self._populate_hidden()
                self._update_stats()

            if self._cancel_flag.is_set():
                self._set_status(f"Cancelled after hidden-data check — {total} files.")
                return

            # 5. Entropy
            self._entropy = []
            if self._run_entropy.get():
                done = [0]
                def _ent_cb(p):
                    done[0] += 1
                    self._set_status(
                        f"Entropy: {done[0]} / {total} — {os.path.basename(p)}")
                self._entropy = ent_mod.analyze_all(
                    [m.path for m in self._metas], progress_cb=_ent_cb)
                self._populate_entropy()

            # 6. Link files to a parsed $MFT (ADS fallback, $SI/$FN risk)
            #    and re-populate metadata with risk scores
            self._link_mft()
            if self._hidden:
                self._populate_hidden()
            self._populate_metadata()

            # 7. Timeline + timestamp anomalies
            self._rebuild_timeline()
            self._update_stats()

            # 8. Hash set match if already loaded
            if self._hashset:
                self._run_hashset_match()

            self._set_status(
                f"Complete — {total} files | "
                f"{sum(1 for s in self._sigs if s.mismatch)} sig mismatches | "
                f"{sum(1 for h in self._hidden if h.is_suspicious)} suspicious | "
                f"{len(self._anomalies)} timestamp anomalies")

        except PermissionError:
            self._set_status("Permission denied — try running as administrator.")
            messagebox.showerror("Permission Error",
                                 "Access denied. Try running ByteProbe as administrator.")
        except FileNotFoundError:
            self._set_status("Directory not found — it may have been moved or deleted.")
            messagebox.showerror("Not Found", "The target directory no longer exists.")
        except OSError as exc:
            self._set_status(f"File system error: {exc}")
            messagebox.showerror("File System Error", str(exc))
        except Exception as exc:
            self._set_status(f"Unexpected error: {exc}")
            messagebox.showerror("Scan error", str(exc))
        finally:
            self._scan_end = datetime.datetime.now()
            self.root.after(0, self._progress.stop)
            self.root.after(0, lambda: self._scan_btn.config(state='normal'))
            self.root.after(0, lambda: self._stop_btn.config(state='disabled'))

    def _update_stats(self):
        def _do():
            self._stat_vars['files'].set(str(len(self._metas)))
            self._stat_vars['mismatches'].set(
                str(sum(1 for s in self._sigs if s.mismatch)))
            self._stat_vars['suspicious'].set(
                str(sum(1 for h in self._hidden if h.is_suspicious)))
            self._stat_vars['anomalies'].set(str(len(self._anomalies)))
            self._stat_vars['si_fn'].set(
                str(sum(1 for a in self._si_fn if a['confidence'] == 'high'))
                if self._mft_records else '—')
        self.root.after(0, _do)

    # ── Table population ──────────────────────────────────────────────────────

    def _populate_metadata(self, filter_text: str = ''):
        sig_map = {s.path: s for s in self._sigs}
        ent_map = {e.path: e for e in self._entropy}
        stomped = {a['record'] for a in self._si_fn if a['confidence'] == 'high'}
        meta_mft = self._meta_mft
        ft = filter_text.lower()

        def _do():
            self._meta_table.clear()
            shown = 0
            for m in self._metas:
                if ft and ft not in m.name.lower() and ft not in m.extension.lower():
                    continue
                risk = hid_mod.compute_risk_score(
                    m,
                    sig_result=sig_map.get(m.path),
                    entropy_result=ent_map.get(m.path),
                    si_fn_anomaly=(m.path in meta_mft and
                                   meta_mft[m.path].record_number in stomped),
                )
                tag = 'warn' if risk >= 60 or m.is_hidden or m.is_system else \
                      'orange' if risk >= 30 else ''
                self._meta_table.insert(
                    [m.path, m.name, m.size,
                     m.created.strftime('%Y-%m-%d %H:%M:%S'),
                     m.modified.strftime('%Y-%m-%d %H:%M:%S'),
                     'Y' if m.is_hidden else '', 'Y' if m.is_system else '',
                     'Y' if m.is_readonly else '', m.owner, m.extension, risk], tag)
                shown += 1
            self._meta_filter_label.config(
                text=f"{shown} of {len(self._metas)} shown" if ft else "")
        self.root.after(0, _do)

    def _filter_metadata(self):
        self._populate_metadata(filter_text=self._meta_search.get().strip())

    def _clear_meta_filter(self):
        self._meta_search.set('')
        self._populate_metadata()

    def _populate_sigs(self):
        def _do():
            self._sig_table.clear()
            for s in self._sigs:
                tag = 'warn' if s.mismatch else ''
                self._sig_table.insert(
                    [s.path, s.declared_ext, ', '.join(s.detected_exts),
                     s.magic_hex, 'YES' if s.mismatch else '', s.note], tag)
        self.root.after(0, _do)

    def _populate_hashes(self):
        def _do():
            self._hash_table.clear()
            for h in self._hashes:
                self._hash_table.insert([h.path, h.md5, h.sha1, h.sha256, h.size, ''])
        self.root.after(0, _do)

    def _populate_hidden(self):
        def _do():
            self._hidden_table.clear()
            for r in self._hidden:
                if not r.is_suspicious:
                    continue
                ads_str = '; '.join(f"{a.stream_name}({a.size}B)" for a in r.ads_streams)
                flg_str = '; '.join(r.suspicion_flags)
                self._hidden_table.insert(
                    [r.meta.path, ads_str or '—', flg_str or '—'], 'warn')
        self.root.after(0, _do)

    def _populate_entropy(self):
        def _do():
            self._entropy_table.clear()
            for e in self._entropy:
                tag = 'warn' if e.is_high_entropy else ''
                self._entropy_table.insert(
                    [e.path, e.entropy, 'YES' if e.is_high_entropy else '', e.note], tag)
        self.root.after(0, _do)

    def _rebuild_timeline(self):
        if not self._metas:
            return
        self._events = tl_mod.build_timeline(
            self._metas, include_accessed=self._tl_incl_accessed.get())
        self._anomalies = tl_mod.find_timestamp_anomalies(self._metas)
        self._refresh_timeline()
        self._populate_anomalies()

    def _refresh_timeline(self):
        def _do():
            kind = self._tl_kind.get()
            events = (self._events if kind == 'all'
                      else tl_mod.filter_by_kind(self._events, kind))
            self._tl_table.clear()
            for e in events:
                tag = 'warn' if (e.is_hidden or e.is_system) else ''
                self._tl_table.insert(
                    [e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.kind,
                     e.path, e.size, e.extension, 'Y' if e.is_hidden else ''], tag)
        self.root.after(0, _do)

    def _populate_anomalies(self):
        def _do():
            self._anomaly_table.clear()
            for a in self._anomalies:
                self._anomaly_table.insert(
                    [a['path'], a['created'], a['modified'], a['delta'], a['note']], 'warn')
        self.root.after(0, _do)

    # ── NTFS $MFT ─────────────────────────────────────────────────────────────

    def _browse_mft(self):
        path = filedialog.askopenfilename(
            title="Select an extracted $MFT or a raw NTFS / disk image",
            filetypes=[('All files', '*.*'), ('Raw images', '*.dd *.raw *.img *.bin')])
        if path:
            self._mft_source.set(path)

    def _use_live_volume(self):
        drive = os.path.splitdrive(self._scan_dir.get().strip())[0]
        if not drive:
            messagebox.showerror("No target", "Choose a target directory on an NTFS drive first.")
            return
        self._mft_source.set(mft_mod.normalise_source(drive))

    def _start_mft_parse(self):
        source = self._mft_source.get().strip()
        if not source:
            messagebox.showerror("Error", "Select an $MFT file, a disk image, or a volume.")
            return
        offset = None
        if self._mft_offset.get().strip():
            try:
                offset = int(self._mft_offset.get().strip(), 0)
                if offset < 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Offset must be a non-negative number of bytes"
                                              " (decimal or 0x hex).")
                return
        self._mft_cancel.clear()
        self._mft_btn.config(state='disabled')
        self._mft_stop_btn.config(state='normal')
        self._progress.start(10)
        self._set_status(f"Parsing $MFT from {source}…")
        threading.Thread(target=self._run_mft_parse, args=(source, offset),
                         daemon=True).start()

    def _stop_mft_parse(self):
        self._mft_cancel.set()
        self._mft_stop_btn.config(state='disabled')

    def _run_mft_parse(self, source: str, offset):
        try:
            records = mft_mod.parse_mft(
                source, volume_offset=offset,
                progress_cb=lambda n: self._set_status(f"$MFT: {n:,} records read…"),
                cancel_flag=self._mft_cancel)
            if self._mft_cancel.is_set():
                self._set_status("$MFT parse cancelled — previous results kept.")
                return
            self._mft_records = records
            self._mft_index = mft_mod.MFTIndex(records)
            self._si_fn = tl_mod.find_si_fn_anomalies(records)
            self._mft_source_used = source

            self._link_mft()
            if self._hidden:
                self._populate_hidden()
            if self._metas:
                self._populate_metadata()
            self._refresh_mft_table()
            self._update_stats()

            in_use = sum(1 for r in records if r.in_use)
            ads = sum(1 for r in records if r.ads)
            linked = f" | {len(self._meta_mft)} scanned files linked" if self._metas else ''
            high = sum(1 for a in self._si_fn if a['confidence'] == 'high')
            self._set_status(
                f"$MFT parsed — {len(records):,} records ({in_use:,} in use) | "
                f"$SI/$FN anomalies: {high} high, {len(self._si_fn) - high} low | "
                f"{ads} with ADS{linked}")
        except mft_mod.MFTError as exc:
            self._set_status(f"$MFT error: {exc}")
            self.root.after(0, lambda: messagebox.showerror("$MFT error", str(exc)))
        except Exception as exc:
            self._set_status(f"$MFT error: {exc}")
            self.root.after(0, lambda: messagebox.showerror("$MFT error", str(exc)))
        finally:
            self.root.after(0, self._progress.stop)
            self.root.after(0, lambda: self._mft_btn.config(state='normal'))
            self.root.after(0, lambda: self._mft_stop_btn.config(state='disabled'))

    def _link_mft(self):
        """Match scanned files to MFT records; add MFT-sourced ADS."""
        self._meta_mft = {}
        if self._mft_index is None or not self._metas:
            return
        root = self._scan_dir.get().strip() or None
        for m in self._metas:
            rec = self._mft_index.lookup(m.path, size=m.size, scan_root=root)
            if rec is not None:
                self._meta_mft[m.path] = rec
        for h in self._hidden:
            rec = self._meta_mft.get(h.meta.path)
            if rec is not None and not h.ads_streams:
                h.ads_streams = hid_mod.ads_from_mft(rec, host_file=h.meta.path)

    @staticmethod
    def _fmt_ft(ts, name: str) -> str:
        """FILETIME with all 7 sub-second digits, so zeroed precision is visible."""
        dt = ts.as_datetime(name) if ts else None
        if dt is None:
            return ''
        return f"{dt:%Y-%m-%d %H:%M:%S}.{ts.subsecond_ticks(name):07d}"

    def _refresh_mft_table(self):
        records  = self._mft_records
        si_fn    = self._si_fn
        show_all = self._mft_show.get() == 'all'
        incl_del = self._mft_incl_deleted.get()
        flagged  = {a['record'] for a in si_fn if a['confidence'] == 'high'}
        fields   = mft_mod.TIMESTAMP_FIELDS

        def _do():
            self._mft_table.clear()
            self._si_fn_table.clear()
            shown = 0
            for r in records:
                if not incl_del and not r.in_use:
                    continue
                is_flagged = r.record_number in flagged
                if not show_all and not is_flagged and not r.ads:
                    continue
                if shown >= MFT_ROW_CAP:
                    break
                fn_ts = r.fn.timestamps if r.fn else None
                tag = 'warn' if is_flagged else 'orange' if r.ads else ''
                self._mft_table.insert(
                    [r.record_number, r.path, 'Y' if r.in_use else 'deleted']
                    + [self._fmt_ft(r.si, n) for n in fields]
                    + [self._fmt_ft(fn_ts, n) for n in fields]
                    + ['; '.join(f":{a.name} ({a.size}B)" for a in r.ads)], tag)
                shown += 1
            for a in sorted(si_fn, key=lambda a: a['confidence'] != 'high'):
                if not incl_del and not a['in_use']:
                    continue
                self._si_fn_table.insert(
                    [a['record'], a['path'], 'Y' if a['in_use'] else 'deleted',
                     a['confidence'].upper(), a['si_created'], a['fn_created'], a['note']],
                    'warn' if a['confidence'] == 'high' else 'orange')
            if records:
                self._mft_summary.config(
                    text=f"{shown:,} of {len(records):,} records shown"
                         f"{' (capped)' if shown >= MFT_ROW_CAP else ''}")
        self.root.after(0, _do)

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _report_kwargs(self):
        return dict(
            examiner=self._report_vars['examiner'].get(),
            case_name=self._report_vars['case'].get(),
            target_path=self._scan_dir.get(),
            scan_start=self._scan_start,
            scan_end=self._scan_end,
            si_fn_anomalies=self._si_fn if self._mft_records else None,
            mft_source=self._mft_source_used,
        )

    def _log_report(self, msg: str, level: str = 'info'):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        prefix = {'ok': '[OK] ', 'err': '[FAILED] ', 'info': '[INFO] '}.get(level, '')
        line = f"[{ts}] {prefix}{msg}\n"
        def _do():
            self._report_log.config(state='normal')
            self._report_log.insert('end', line, level)
            self._report_log.see('end')
            self._report_log.config(state='disabled')
        self.root.after(0, _do)

    def _validate_report_fields(self) -> bool:
        examiner = self._report_vars["examiner"].get().strip()
        case = self._report_vars["case"].get().strip()
        if not examiner or not case:
            messagebox.showerror("Validation", "Examiner name and case name are required.")
            return False
        if len(examiner) > 100 or len(case) > 100:
            messagebox.showerror(
                "Validation", "Examiner and case name must each be under 100 characters.")
            return False
        return True

    def _export_csv(self):
        if not self._validate_report_fields():
            return
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        out_dir = filedialog.askdirectory(title="Select output folder")
        if not out_dir:
            return
        try:
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            reporter.export_metadata_csv(self._metas,  f"{out_dir}/metadata_{ts}.csv")
            reporter.export_hashes_csv(self._hashes,   f"{out_dir}/hashes_{ts}.csv")
            reporter.export_signatures_csv(self._sigs, f"{out_dir}/signatures_{ts}.csv")
            reporter.export_timeline_csv(self._events, f"{out_dir}/timeline_{ts}.csv")
            n = 4
            if self._entropy:
                reporter.export_entropy_csv(self._entropy, f"{out_dir}/entropy_{ts}.csv")
                n += 1
            if self._mft_records:
                reporter.export_mft_csv(self._mft_records, f"{out_dir}/mft_records_{ts}.csv")
                reporter.export_si_fn_csv(self._si_fn, f"{out_dir}/si_fn_anomalies_{ts}.csv")
                n += 2
            self._log_report(f"CSV bundle ({n} files) → {out_dir}", level='ok')
        except Exception as exc:
            self._log_report(f"CSV export failed: {exc}", level='err')
            messagebox.showerror("Export Error", str(exc))

    def _export_html(self):
        if not self._validate_report_fields():
            return
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.html', filetypes=[('HTML', '*.html')],
            initialfile='byteprobe_report.html')
        if not path:
            return
        try:
            reporter.export_html_report(
                path, self._metas, self._hashes, self._sigs,
                self._hidden, self._events, **self._report_kwargs())
            self._log_report(f"HTML report → {path}", level='ok')
        except Exception as exc:
            self._log_report(f"HTML export failed: {exc}", level='err')
            messagebox.showerror("Export Error", str(exc))

    def _export_pdf(self):
        if not self._validate_report_fields():
            return
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        if not reporter.HAS_REPORTLAB:
            messagebox.showinfo("ReportLab missing",
                                "Install reportlab:\n  pip install reportlab")
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.pdf', filetypes=[('PDF', '*.pdf')],
            initialfile='byteprobe_report.pdf')
        if not path:
            return
        try:
            reporter.export_pdf_report(
                path, self._metas, self._hashes, self._sigs,
                self._hidden, self._events, **self._report_kwargs())
            self._log_report(f"PDF report → {path}", level='ok')
        except Exception as exc:
            self._log_report(f"PDF export failed: {exc}", level='err')
            messagebox.showerror("Export Error", str(exc))

    # ── VirusTotal ────────────────────────────────────────────────────────────

    def _start_vt_check(self):
        if not self._hashes:
            messagebox.showwarning("No hashes", "Run a scan first to generate file hashes.")
            return
        api_key = self._vt_api_key.get().strip()
        if not api_key:
            messagebox.showerror("API Key Missing",
                                 "Enter your VirusTotal API key.\n"
                                 "Get a free key at virustotal.com")
            return
        self._cancel_flag.clear()
        self._vt_btn.config(state='disabled')
        self._vt_stop_btn.config(state='normal')
        self._vt_table.clear()
        self._vt_results = []
        threading.Thread(
            target=self._run_vt_check,
            args=(api_key,), daemon=True).start()

    def _stop_vt_check(self):
        self._cancel_flag.set()
        self._vt_stop_btn.config(state='disabled')
        self._set_status("VirusTotal check cancelled.")

    def _run_vt_check(self, api_key: str):
        total = len(self._hashes)
        self._set_status(f"VirusTotal: checking {total} files — this may take a while…")

        def _progress(done, total, path):
            self._set_status(
                f"VirusTotal: {done} / {total} — {os.path.basename(path)}")
            self.root.after(0, lambda: self._vt_progress_label.config(
                text=f"{done} / {total} checked"))

        try:
            self._vt_results = vt_mod.check_all(
                self._hashes, api_key,
                progress_cb=_progress,
                cancel_flag=self._cancel_flag)

            self._populate_vt()
            mal = sum(1 for r in self._vt_results if r.verdict == 'malicious')
            sus = sum(1 for r in self._vt_results if r.verdict == 'suspicious')
            self._set_status(
                f"VirusTotal done — {len(self._vt_results)} checked | "
                f"{mal} malicious | {sus} suspicious")
        except Exception as exc:
            self._set_status(f"VirusTotal error: {exc}")
            messagebox.showerror("VirusTotal Error", str(exc))
        finally:
            self.root.after(0, lambda: self._vt_btn.config(state='normal'))
            self.root.after(0, lambda: self._vt_stop_btn.config(state='disabled'))
            self.root.after(0, lambda: self._vt_progress_label.config(text=""))

    def _populate_vt(self):
        def _do():
            self._vt_table.clear()
            for r in self._vt_results:
                if r.verdict == 'malicious':
                    tag = 'warn'
                elif r.verdict == 'suspicious':
                    tag = 'orange'
                elif r.verdict == 'clean':
                    tag = 'ok'
                else:
                    tag = ''
                det = f"{r.malicious} / {r.total_engines}" if r.total_engines else r.error
                self._vt_table.insert(
                    [r.path, r.sha256, r.malicious, r.suspicious,
                     r.total_engines, r.verdict.upper(), r.permalink], tag)
        self.root.after(0, _do)

    # ── Hash set ──────────────────────────────────────────────────────────────

    def _load_hashset(self):
        path = filedialog.askopenfilename(
            title='Select hash set (NSRL CSV/SQLite = known-good, or a known-bad list)',
            filetypes=[('Hash sets', '*.txt *.csv *.db *.sqlite *.sqlite3'),
                       ('All files', '*.*')])
        if not path:
            return
        try:
            self._hashset = hash_mod.load_hash_database(path)
        except Exception as exc:
            messagebox.showerror('Hash set', f'Could not load hash set:\n{exc}')
            return
        self._hashset_label.config(
            text=f'Loaded {len(self._hashset):,} hashes ({self._hashset.kind}) '
                 f'from {self._hashset.name}')
        if self._hashes:
            self._run_hashset_match()

    def _run_hashset_match(self):
        if not self._hashset:
            return
        matches = hash_mod.match_against_hashset(self._hashes, self._hashset)
        match_paths = {m.path for m in matches}
        good = self._hashset.kind == hash_mod.KNOWN_GOOD
        label = 'KNOWN-GOOD' if good else 'KNOWN-BAD'
        self._hash_table.clear()
        for h in self._hashes:
            matched = label if h.path in match_paths else ''
            # Known-bad matches are highlighted; known-good (NSRL) are not.
            tag = 'warn' if (matched and not good) else ''
            self._hash_table.insert(
                [h.path, h.md5, h.sha1, h.sha256, h.size, matched], tag)
        if good:
            msg = (f'{len(matches)} of {len(self._hashes)} file(s) are known-good '
                   '(standard files in the NSRL) and can be deprioritised.\n'
                   f'{len(self._hashes) - len(matches)} file(s) are not in the set '
                   'and still need review.')
        else:
            msg = (f'{len(matches)} file(s) matched the known-bad hash set.\n'
                   'Matched files are highlighted red in the Integrity tab.')
        messagebox.showinfo('Hash Set Results', msg)

    # ── About ─────────────────────────────────────────────────────────────────

    def _show_about(self):
        messagebox.showinfo(
            "About ByteProbe",
            "ByteProbe v1.0\n"
            "Digital Forensics Toolkit\n\n"
            "Capabilities:\n"
            "  • File metadata & MAC timestamps\n"
            "  • Magic-byte signature verification\n"
            "  • MD5 / SHA-1 / SHA-256 hashing\n"
            "  • NTFS $MFT parsing ($SI / $FN timestamps)\n"
            "  • $SI vs $FN timestomping detection\n"
            "  • NTFS alternate data stream detection\n"
            "  • VirusTotal hash lookup (API v3)\n"
            "  • Shannon entropy analysis\n"
            "  • Timeline reconstruction\n"
            "  • CSV / HTML / PDF report export\n\n"
            "Requires Python 3.10+\n"
            "Optional: pip install reportlab  (PDF export)")

    # ── Reset ─────────────────────────────────────────────────────────────────

    def _reset(self):
        if not messagebox.askyesno('Clear', 'Clear all scan data for a new case?'):
            return
        self._metas = []
        self._hashes = []
        self._sigs = []
        self._hidden = []
        self._events = []
        self._entropy = []
        self._anomalies  = []
        self._vt_results = []
        self._mft_records = []
        self._mft_index = None
        self._si_fn = []
        self._meta_mft = {}
        self._mft_source_used = ''
        self._mft_source.set('')
        self._mft_offset.set('')
        self._mft_summary.config(text='')
        for tbl in [self._meta_table, self._sig_table, self._hash_table,
                    self._hidden_table, self._tl_table, self._anomaly_table,
                    self._entropy_table, self._vt_table,
                    self._mft_table, self._si_fn_table]:
            tbl.clear()
        self._scan_dir.set('')
        self._meta_search.set('')
        self._meta_filter_label.config(text='')
        self._hashset_label.config(text='No hash set loaded')
        for var in self._stat_vars.values():
            var.set('—')
        self._scan_btn.config(state='normal')
        self._stop_btn.config(state='disabled')
        self._set_status('Cleared — ready for new case.')

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self._status_var.set(msg))

    def run(self):
        self.root.mainloop()
