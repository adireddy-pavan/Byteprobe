> **Windows friend handoff (16 October 2026):** Start with `FRIEND_WINDOWS_STEP_BY_STEP.md` and `RUN_1_WINDOWS_BASIC.cmd`. The latest Linux/Xvfb suite contained 139 passing tests; the 123-test numbers below describe a prior release. Save Windows results in the automatically generated `verification_results/` folder. Do not run W5/W6 on the system drive.

# ByteProbe — Windows File Analysis Tool for Digital Forensics

A read-only forensic triage tool (Python 3.10+, Tkinter GUI).

> **Open this folder first.** After unzipping, open the `ByteProbe` folder (the one that contains
> `main.py`, `core/`, `gui/`, `tests/` and this README) and run every command below from inside it.

## What was tested, and what was not

| Area | How it was tested | Not tested |
|---|---|---|
| `$MFT` parser (`core/mft.py`) | Synthetic NTFS records built byte-by-byte from the specification; 3 real MFT records from the `mft` project; one real 13 MB sample `$MFT` compared with an independent parser (100% field agreement on 13,064 records) | **No live Windows NTFS volume** (`\\.\C:`), no real disk image (MBR/GPT parsing is tested on synthetic images only), no E01/AFF |
| `$SI`/`$FN` timestomping | Rules unit-tested; alert rate measured on the sample `$MFT`; six attack profiles injected into a copy of it | Real timestomping tools were not run against a live system; thresholds were tuned on the same single (Windows XP-era) sample |
| ADS | Parsed from `$MFT` records (10 in the sample) | The Windows API route (`FindFirstStreamW`) was not run, because it needs Windows |
| VirusTotal | `tests/test_virustotal.py` with **mocked** API responses; the GUI tab was only viewed in its ready state | **No live VirusTotal lookup** has been made |
| NSRL / hash sets | Unit tests with a synthetic NSRL-format CSV and a synthetic SQLite file | **The real NSRL RDS was not used** (it is hundreds of GB) |
| Signature / entropy | Unit tests, plus a labelled **synthetic** corpus (`evaluation/evaluate_detectors.py`) compared with libmagic | No real-world or malware corpus |
| GUI | GUI-only and complete test suites run under Linux/Xvfb after a mainloop/modal-dialog test-harness fix; screenshots in `screenshots/current/` | Not run on Windows or macOS for this version |
| Owner lookup (pywin32) | Not tested (Windows only) | |

`python -m unittest discover -s tests -t .` discovers **123 tests: 118 pass and 5 are skipped**
(the GUI smoke tests, which `unittest` skips when no display is attached — see *GUI tests* below).
No test fails. They check the code against synthetic
and sample data. They are not a validation against real casework.

| Module | What it does |
|---|---|
| `core/metadata.py` | File metadata, MAC timestamps, attributes, owner |
| `core/signatures.py` | Magic-byte signature vs. extension mismatch. RIFF subtype is checked (WAV/AVI/WEBP), BMP needs its reserved bytes, and a file with an unrecognised header but an extension that requires one (`.png`, `.exe`, `.pdf`...) is flagged |
| `core/hasher.py` | MD5 / SHA-1 / SHA-256 in one pass; duplicates (grouped by SHA-256); hash-set matching on MD5, SHA-1 or SHA-256. Loads NSRL CSV (`NSRLFile.txt`), a modern NSRL RDS SQLite file (queried, not loaded into memory) or a plain list. NSRL matches are labelled **known-good** (deprioritise), other lists **known-bad** (investigate) |
| `core/entropy.py` | Shannon entropy (0–8 bits/byte); flags > 7.2 as encrypted/packed/compressed. Also scans 4 KB blocks, so a packed or encrypted section inside an otherwise normal file (4+ blocks above 7.5 bits) is reported |
| `core/mft.py` | **NTFS `$MFT` parser**: FILE records, fixups, data runs, `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps (all four each), named `$DATA` (ADS), full paths. Reads an extracted `$MFT`, a raw volume/disk image (MBR or GPT), or a live volume (`\\.\C:`, Windows, Administrator) |
| `core/timeline.py` | Timeline, plus **`$SI` vs `$FN` timestomping detection** (`find_si_fn_anomalies`) and the older low-confidence OS-timestamp check |
| `core/hidden_data.py` | ADS via `FindFirstStreamW` on Windows, **falling back to the parsed `$MFT`** on any OS; suspicion flags; 0–100 risk score |
| `core/virustotal.py` | SHA-256 lookup against VirusTotal API v3 (free-tier rate limit: 16 s between requests) |
| `core/reporter.py` | CSV bundle, HTML and PDF reports, including the `$MFT` and `$SI`/`$FN` results |

## Running

From inside the `ByteProbe` folder:

```bash
pip install -r requirements.txt   # optional: reportlab (PDF), pywin32 (Windows owner/attributes)
python main.py
```

**NTFS $MFT tab:** choose an extracted `$MFT`, a raw image, or (on Windows) the target's
volume, then click *Parse $MFT*. If a directory scan has also been run, scanned files are
matched to their MFT records by path and size. The MFT's ADS then appear in *Covert Data*,
and a high-confidence `$SI`/`$FN` anomaly adds to the file's risk score.

**VirusTotal tab:** run a scan first, then enter a VirusTotal API key. Free keys are
limited to 4 lookups per minute.

## Timestomping detection

User-mode APIs such as `SetFileTime` can rewrite the `$STANDARD_INFORMATION` timestamps. The
`$FILE_NAME` timestamps are written by the NTFS driver on create, rename or move. A record is
flagged when any of these hold:

- `$SI` Created is earlier than `$FN` Created (tolerance: 2 s)
- `$SI` MFT-changed is earlier than `$FN` MFT-changed
- `$SI` Created, or all four `$SI` values, have zero sub-second precision while `$FN` does not

`$SI` Modified is deliberately not compared: copying or extracting a file preserves an
old Modified time legitimately. Findings are rated **low confidence** when the `$SI` Created
value is shared by 5 or more records. That is the installer pattern (Windows setup stamps
thousands of files with the same build time), and it is the main source of benign alerts.

## Risk score weights (capped at 100)

| Indicator | Weight |
|---|---|
| `$SI`/`$FN` timestamp anomaly (high confidence) | +40 |
| Extension / signature mismatch | +35 |
| Hidden + System attributes | +30 |
| Double extension (e.g. `invoice.pdf.exe`) | +25 |
| High entropy (> 7.2) | +20 |
| Executable in a temp directory | +20 |
| Risky extension | +10 |

## Installation

Requires **Python 3.10 or newer** (developed and verified on 3.12 and 3.13).

```bash
python -V                          # confirm 3.10+
pip install -r requirements.txt    # reportlab (PDF export) — optional
pip install pywin32                # Windows only: file ownership and native ADS enumeration
pip install mft                    # optional: independent reference parser, used by evaluate_mft.py
```

Every analysis module runs on the Python standard library alone. The optional packages add:

| Package | Needed for | Without it |
|---|---|---|
| `reportlab` | PDF report export | HTML and CSV export still work |
| `pywin32` | Windows file ownership, native ADS enumeration | Owner reported as unavailable; ADS read from a parsed `$MFT` instead |
| `mft` | Parser-agreement comparison in `evaluation/evaluate_mft.py` | That one section is skipped; everything else runs |

The public `$MFT` sample is **not bundled**. `evaluation/evaluate_mft.py` downloads it on
first run (13,402,112 bytes, SHA-256
`c78f4968345b70783fbf6573d86c4bf300295ae26ddde4033dd1037b802e13c1`) and caches it at
`evaluation/data/MFT`. To supply your own instead, pass the path as the first argument.

### Windows setup

`pywin32` is required for the Windows-only features. After installing it, follow
[`docs/WINDOWS_VALIDATION.md`](docs/WINDOWS_VALIDATION.md), which gives a step-by-step
procedure for verifying ownership resolution, attribute flags, ADS discovery through the
Windows API, live-volume `$MFT` access and report exports, with a results table to complete.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

Result in a headless container (Python 3.13.16):

```
Ran 123 tests in 0.26s

OK (skipped=5)
```

123 tests are discovered; 118 pass, 5 skip, none fail. The five skips are the GUI
smoke tests described below. Running the same command on a machine with a display
executes all 123. A verbatim transcript of the run above is kept at
[`evaluation/logs/unittest_2026-10-14.log`](evaluation/logs/unittest_2026-10-14.log).

The tests use the standard library only:

- **`test_mft.py`:** synthetic NTFS records and volumes are built byte-by-byte from the
  specification (fragmented, sparse, MBR, GPT, torn records). It also checks three real
  Windows MFT records against values cross-checked with an independent parser.
- **`test_timeline.py`:** the `$SI`/`$FN` rules and the confidence levels.
- **`test_hidden_data.py`:** the risk weights and the ADS fallback.
- **`test_hasher.py`:** RFC 1321 and FIPS 180-2 test vectors, chunk boundaries, the avalanche effect, NSRL CSV and SQLite loading, SHA-1 matching and known-good/known-bad labelling.
- **`test_signatures.py`:** renamed executables, RIFF subtypes, the BMP check, and unknown headers.
- **`test_entropy.py`:** exact analytical values, the documented false negatives, and the block-wise scan.
- **`test_virustotal.py`:** the API is mocked, so no network is needed.

### GUI tests

`tests/test_gui_smoke.py` contains five headless smoke tests covering window
construction, the presence and selectability of all nine tabs, a full background scan
with result population, and reset. They **skip** where Tkinter or a display is
unavailable. On Linux/Xvfb, the corrected harness executes all five using a real Tk
event loop and a mocked reset confirmation. The 15 October 2026 Linux/Xvfb
run passed all 123 tests; see `evaluation/logs/unittest_xvfb_2026-10-15.log`.
Windows remains untested in this update. **A skipped test is not a passed test**: these five are only evidence about
the GUI once they have been run on a host with a display (see
[`docs/WINDOWS_VALIDATION.md`](docs/WINDOWS_VALIDATION.md), step W1).

```bash
xvfb-run -a python -m unittest tests.test_gui_smoke -v     # Linux
python -m unittest tests.test_gui_smoke -v                 # Windows
```

## Evaluation

```bash
pip install mft                       # optional independent reference parser
python evaluation/evaluate_mft.py     # downloads a real 13 MB $MFT on first run
```

The script compares ByteProbe with the reference parser on a real Windows `$MFT`, measures the
alert rate on unmodified data, and runs a controlled timestomping-injection experiment against
the old OS-timestamp check. The results are in [`evaluation/RESULTS.md`](evaluation/RESULTS.md).

```bash
python evaluation/evaluate_detectors.py   # signature + entropy on a labelled synthetic corpus
```

This compares the signature check with libmagic (`file`) and measures precision and recall for
signature and entropy detection (results: [`evaluation/RESULTS_DETECTORS.md`](evaluation/RESULTS_DETECTORS.md)).
The corpus is synthetic and built by the same author as the detectors, so it tests the logic, not
real-world performance.

## Verifying this package

```bash
sha256sum -c SHA256SUMS.txt
```

`SHA256SUMS.txt` lists the SHA-256 of every other file in the archive. A file cannot
contain its own digest, so the digest of the ZIP itself is supplied alongside the ZIP
rather than inside it, and re-compressing an unchanged tree changes the archive digest
while leaving every per-file digest the same. [`EVIDENCE.md`](EVIDENCE.md) records the
full verification log, and `evaluation/logs/` holds the raw console transcripts behind it.

## Known limitations

- E01/AFF images are not read. Convert them to raw first (e.g. `ewfexport`).
- `$UsnJrnl` and `$LogFile` are not parsed. Timestomping that also rewrites `$FN` (SetMACE,
  rename after stomp) or that forward-dates `$SI` is not detected (see RESULTS.md, profiles D–F).
- ADS detection through the Windows API needs Windows. On other platforms it needs a parsed `$MFT`.
- On Linux and macOS, `os.stat` "created" is the inode-change time, so the OS-timestamp check is weak there.
- NSRL: the RDS SQLite lookup assumes a `FILE` table with `sha256`/`sha1`/`md5` columns and is slow without an index on those columns.
- Not compared against Autopsy, FTK or MFTECmd; the `$MFT` results are checked against the `mft` crate only.
- The 4 KB block scan is informational. It does not add to the risk score.
- Entropy misses compressed data from highly redundant input (about 6.9 bits) and any file
  under 148 bytes (maximum entropy is log2(n)).

## 15 October 2026 resubmission verification update

The GUI-test harness was corrected to enter `Tk.mainloop()` and mock the
confirmation dialogue. The retained virtual-display transcript shows **123/123
passed**; headless operation still skips five GUI tests. This is **not** Windows
validation. See [`docs/RESUBMISSION_STATUS.md`](docs/RESUBMISSION_STATUS.md) for
remaining obligations, [`docs/INDEPENDENT_BENCHMARK_PROTOCOL.md`](docs/INDEPENDENT_BENCHMARK_PROTOCOL.md)
for a defensible external-tool comparison, and
[`docs/SCREENCAST_CHECKLIST.md`](docs/SCREENCAST_CHECKLIST.md) for video coverage.

## 16 October 2026 controlled-validation extensions

The current package contains **128 tests** (123 original + 5 verification-script
regressions). See `evaluation/logs/full_suite_2026-10-16.log` for the latest Linux/Xvfb
rerun, and `docs/RESEARCH_UPDATE_2026-10-16.md` for dated changes.

- `python evaluation/evaluate_controlled_timestamps.py` regenerates a **640-record
  author-built** controlled study, Wilson intervals, and a threshold sensitivity
  matrix. It is **not** blinded external validation; results on deliberately
  challenging synthetic benign/attack patterns must not be generalized.
- `python evaluation/compare_mftecmd.py --help` provides a record+sequence-keyed
  comparison against MFTECmd output **once an actual independent reference CSV
  from the same MFT is available**. Current tests use deliberately mocked CSV.
- `python tools/run_windows_checks.py --output windows_evidence` performs
  disposable-file checks W1–W4 and W7 **only on Windows**; W5/W6 require an
  authorized examination environment and manual evidence. It refuses Linux
  to prevent a false claim of Windows validation.
- `docs/EXTERNAL_VALIDATION_AND_SUBMISSION.md` and `docs/GITHUB_PUBLISH.md`
  spell out remaining evidence; neither a GitHub update nor screencast has been
  performed by this revision.

The October 15 transcripts below refer to the previous 123-test revision and
remain in the repository as historical evidence, not as the newest test count.

## October 16 external-evidence readiness supplement

The supplied source now contains **131 automated tests** (128 pre-existing tests plus three evidence-inventory regression tests). In the Linux/Xvfb environment they executed with no failures/skips on 16 October 2026; see `evaluation/logs/verified_linux_suite_131_2026-10-16.log`. This is not Windows verification.

A GitHub Actions workflow at `.github/workflows/windows-validation.yml` is ready to run genuine automated Windows smoke tests W1–W4 and W7 once the owner publishes this source to GitHub. W5/W6, an independent second NTFS source, MFTECmd same-input comparison, real NSRL/VT tests, final Windows screencast, authenticated supervision records, signed declaration and online GitHub commit verification remain outstanding. The `tools/audit_submission_evidence.py` utility checks evidence inventory without manufacturing any missing proof. `docs/FINAL_SCREENCAST_CAPTURE_SCRIPT.md` provides the authentic recording procedure.



### Native Windows W5/W6 laboratory check (prepared, NOT yet run)

The optional `tools/run_windows_w5_w6_lab.py` performs a one-file disposable Created-time manipulation and read-only live-volume parse on a Windows 10/11 NTFS host with Administrator rights. Run it only with the explicit `--confirm-disposable-test` option after reviewing `docs/THREE_TECHNICAL_VALIDATIONS_EXACT_STEPS.md`. Linux test results are not Windows evidence.

The independent MFTECmd comparison now retains a separate list of unmatched record keys and correctly converts explicit time-zone offsets before comparing reference timestamps. It still requires an authentic MFTECmd export.
