# ByteProbe — Verification Evidence Log

Generated: 2026-10-14 16:58 UTC

## 1. Environment
```
Python  : Python 3.13.16
Platform: Linux 6.18.44-fc-v114 x86_64
libmagic: file-5.45
mft       : 0.7.0
reportlab : 5.0.1
pywin32   : not installed
```

## 2. Package integrity

A file cannot contain its own SHA-256, so the digest of the delivered archive
is **not** quoted here. Integrity is instead established per file:

* `SHA256SUMS.txt` in the root of this archive lists the SHA-256 of every
  other file in it. Verify with:

```
sha256sum -c SHA256SUMS.txt
```

* The digest of the archive itself is supplied beside the archive as
  `ByteProbe_FINAL.zip.sha256` at submission time. Re-compressing an
  unchanged tree produces a different archive digest (ZIP stores timestamps
  and compression settings), which is why the per-file manifest above, not
  the archive digest, is the authoritative record of content.

Superseded packages. An earlier archive, `neehanth code.zip`, was submitted
with the original dissertation; its digest
`2fc77ad395979dfb873cd5d6682cc0d771cf58e67e3904991aba004f2efe63e3` identifies
that older submission only. It predates the GUI smoke tests, the Windows
validation procedure, this evidence log and the raw run logs, and should not
be confused with the present package.

Core module checksums (unchanged by re-packaging, so these are stable across
archive rebuilds):
```
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  core/__init__.py
  b6e722ba8a44e0449ebe7493023f0f8726f15ca2edab42a30571951aaa9a4283  core/entropy.py
  5b412e01f5eec8784e9398f94632ecb8af58ba58fc7703832595befba1bd3d8c  core/hasher.py
  9fd9391d1f482609454bdad0f7046485ddb7c5464b4aff04d6cee5ce58838fee  core/hidden_data.py
  39c0229f0406d27c505d9aaa78c550a591a1fcbfdaeea9a71da9c6be1a8e7fd9  core/metadata.py
  3479cb5ffd9a47ea1aea68f6cd75453578b56d9d3c0ee940c38b8d45f34f68b3  core/mft.py
  04abc116cdbcf8c25cc444c19757f4ef5c7939befe288ae5af3e4174a04a387d  core/reporter.py
  85e21d656523e9f74652c8a91dc4a3e48ea77c824ce94f7484606386c44321bb  core/signatures.py
  323524c1798c90c2aee3757830154e6fc62127e199d33e8eb59d5666aca98d74  core/timeline.py
  065d5b910952d8d0d7e8523b65c1f5cbcc7893e64467dc46919bfa5e2fa6ddf8  core/virustotal.py
```

## 3. Unit test suite

Command:
```
python -m unittest discover -s tests -t . -v
```
Result in the tested environment (headless Linux container, Python 3.13.16):
```
----------------------------------------------------------------------
Ran 123 tests in 0.263s

OK (skipped=5)
```

**123 tests discovered, 118 passed, 5 skipped, 0 failed.** The five skips are
the GUI smoke tests in `tests/test_gui_smoke.py`; `unittest` skips them
automatically when Tkinter cannot open a display, which is the case in a
headless container. They are not failures, and they are not evidence that the
GUI works either — that requires the run recorded in
`docs/WINDOWS_VALIDATION.md` step W6 on a host with a display. The report
states the result in exactly this form rather than claiming "123 passing
tests".

The complete verbose transcript, including the five skip lines, is retained at
`evaluation/logs/unittest_2026-10-14.log`.

Tests per module (as discovered):
```
  test_entropy.py    : 18
  test_gui_smoke.py  :  5   (skipped headless)
  test_hasher.py     : 16
  test_hidden_data.py: 10
  test_mft.py        : 37
  test_signatures.py :  9
  test_timeline.py   : 16
  test_virustotal.py : 12
  -------------------------
  total              : 123
```

## 4. NTFS $MFT benchmark against the independent reference parser

Command:
```
pip install mft            # independent Rust-backed reference parser
python evaluation/evaluate_mft.py
```
Sample acquired by the script on first run from the repository in reference [46]:
```
  file   : evaluation/data/MFT
  bytes  : 13,402,112
  sha256 : c78f4968345b70783fbf6573d86c4bf300295ae26ddde4033dd1037b802e13c1
```

Raw console transcript retained at `evaluation/logs/mft_benchmark_2026-10-14.log`.
The excerpt below is taken from that file; the sample is not redistributed in
this archive, so the digest above is the means of re-verifying the input.

Recorded output (parser agreement section):
```
## 1. Parser accuracy compared with an independent reference implementation

Reference: `mft` crate (Rust) Python bindings, 0.51 s. Records compared: 13,064 (reference-only: none, ByteProbe-only: none).

| Field | Agreeing / compared | Agreement |
|---|---|---|
| Allocated (in-use) flag | 13,064 / 13,064 | 100.0% |
| Directory flag | 13,064 / 13,064 | 100.0% |
| $SI timestamps (all four) | 13,064 / 13,064 | 100.0% |
| $FILE_NAME set (name, parent, 4 timestamps) | 13,064 / 13,064 | 100.0% |
| ADS names | 13,064 / 13,064 | 100.0% |
| Full path (in-use records) | 11,833 / 11,833 | 100.0% |

## 2. Alerts on unmodified real data
```

Record counts:
```
ByteProbe parsed **13,064** base records (11,837 in use, 1,227 deleted) in **0.23 s**; 0 record(s) failed the fixup check; 10 record(s) carry named $DATA (ADS).
```

## 5. Six controlled timestomping-injection profiles

Seed 20260930, 500 records per profile. Same command as Section 4; the script runs both experiments.

Detection rates:
```
| Profile | Attack | Landed | Reference agrees | $SI/$FN (any) | $SI/$FN (high confidence) | os.stat baseline |
|---|---|---|---|---|---|---|
| A | Backdate Created+Modified to a whole-second date (timestomp.exe / PowerShell `.CreationTime = "2019-01-01 09:00"`) | 500/500 | 500/500 | 100.0% | **100.0%** | 44.8% |
| B | Backdate all four $SI values with random sub-second ticks (careful tool, keeps 100 ns precision) | 500/500 | 500/500 | 100.0% | **100.0%** | 52.2% |
| C | Change only $SI Modified to an earlier precise time | 500/500 | 500/500 | 0.0% | **0.0%** | 100.0% |
| D | Forward-date Created/Modified to a later precise time (hide a file among newer ones) | 500/500 | 500/500 | 0.0% | **0.0%** | 49.6% |
| E | Whole-second backdate of $SI AND $FN together (SetMACE-style / rename trick copies $SI into $FN) | 500/500 | 500/500 | 0.0% | **0.0%** | 0.0% |
| F | Copy all four $SI values from a random \\WINDOWS\\system32 file (`timestomp -f`, `touch -r`) | 500/500 | 500/500 | 94.2% | **28.0%** | 29.2% |

```

Alert rates on untouched records:
```
| Method | Records flagged |
|---|---|
| os.stat baseline (modified < created) | 2,346 (19.8%) |
| $SI/$FN rules, no tolerance, no context | 5,255 (44.4%) |
| $SI/$FN rules, 2 s tolerance (all confidences) | 4,904 (41.4%) |
| $SI/$FN rules, **high confidence only** (Created value shared by < 5 records) | **917 (7.7%)** |

False-positive rate on the 11,333 untouched in-use records of the same volume: $SI/$FN any = 43.3%, $SI/$FN high confidence = **8.1%**, os.stat baseline = 20.7%.
```

## 6. 300-file synthetic detector corpus (signature + entropy vs libmagic)

Command:
```
python evaluation/evaluate_detectors.py
```
Output:
```
Corpus: 300 files, 90 wrong-extension, 120 high-entropy content

| Signature check | Precision | Recall |
|---|---|---|
| ByteProbe | 100.0% | 100.0% |
| libmagic `file` | 100.0% | 100.0% |

| Entropy check (> 7.2) | Precision | Recall |
|---|---|---|
| ByteProbe | 100.0% | 100.0% |

Note: ZIP archives are compressed, so they are high-entropy by design. Entropy alone cannot separate legitimate compression from encryption or packing, which is why ByteProbe combines it with signature and extension checks.
```

## 7. Report export verification (core/reporter.py)

All seven CSV exporters, the HTML report and the optional PDF report were exercised against a
five-file fixture containing a signature mismatch, a high-entropy file, a double-extension
executable and a filename containing the characters `&`, `<` and `>` to test escaping.

```
Export                 Bytes      Rows/Status
----------------------------------------------------
metadata.csv                929   5 data rows
hashes.csv                  894   5 data rows
signatures.csv              688   5 data rows
timeline.csv                924   10 data rows
entropy.csv                 341   5 data rows
mft.csv                     368   1 data rows
si_fn.csv                   256   1 data rows
report.html                6347   generated
report.pdf                 4007   generated
report.pdf                        generated

HTML escaping  : '&' -> True | '<' -> True
Raw '<notes>' leaked: False
Audit metadata : examiner True | case True | tool version True
SI/FN section  : True
Failure path   : raises FileNotFoundError as expected
```

All seven CSV files, the HTML report and the PDF report were produced. Attacker-controlled
filename characters are HTML-escaped (no raw markup reaches the report), the chain-of-custody
metadata is present, the $SI/$FN section renders, and an unwritable destination raises
FileNotFoundError rather than failing silently.

## 8. GUI verification

`tests/test_gui_smoke.py` adds five automated tests covering window construction, the presence
and selectability of all nine tabs, a full background scan with result population, and reset.
They skip where Tkinter or a display is unavailable and execute on Windows or under Xvfb.

```
----------------------------------------------------------------------
Ran 123 tests in 0.318s

OK (skipped=5)
```

On this container Tkinter is not installed, so the five GUI tests skip and 118 execute.
**Status: not verifiable in this environment.** The procedure in `docs/WINDOWS_VALIDATION.md`
must be run on Windows to produce this evidence.

## 9. Windows-specific validation

**Status: not completed.** The following depend on the Windows API or a live NTFS volume and
have never been executed end to end:

- file ownership resolution via pywin32 (`core/metadata.py`)
- Hidden and System attribute flags from the real API
- ADS enumeration via FindFirstStreamW / FindNextStreamW (`core/hidden_data.py`)
- live-volume `\\\\.\\C:` $MFT access (`core/mft.py`)
- timestamp manipulation performed with real Windows tooling rather than byte injection

`docs/WINDOWS_VALIDATION.md` gives a seven-step procedure (W1\u2013W7) with commands and a results
table. This is the largest outstanding gap in the evaluation and is stated as such in the report.

## 10. Temporary-directory regression

```
101:_TEMP_DIRS  = ('\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '/tmp/', '/var/tmp/')
118:    for tmp in _TEMP_DIRS:
188:    for tmp in _TEMP_DIRS:

59:    def test_unix_temp_dirs_scored_like_flags(self):
```
One shared `_TEMP_DIRS` constant is used by both `_suspicion_flags()` (line 118) and
`compute_risk_score()` (line 188), so the numeric score and the explanatory flag cannot diverge.
The regression test asserts that agreement for POSIX-style paths, which is where the original
defect appeared.

## 11. Report-to-code correspondence

Every quantitative claim in the report was checked against the submitted archive:

| Claim in report | Source in code | Status |
|---|---|---|
| Nine core analysis modules | `core/*.py` — 9 files present | verified |
| Nine GUI tabs | 9 `nb.add` calls in `gui/app.py` | verified |
| Risk weights 40/35/30/25/20/20/10 | `compute_risk_score()`, `core/hidden_data.py` | verified |
| Two-second tolerance | `DEFAULT_TOLERANCE_SECONDS = 2.0`, `core/timeline.py` | verified |
| Bulk threshold of five records | `BULK_THRESHOLD = 5`, `core/timeline.py` | verified |
| Entropy flag at 7.2 bits/byte | `HIGH = 7.2`, `core/entropy.py` | verified |
| 4 KiB region scan, four blocks | `BLOCK = 4096`, `high_blocks >= 4` | verified |
| VirusTotal 16-second interval | `RATE_WAIT = 16`, `core/virustotal.py` | verified |
| 404/401/429 handling | `check_hash()`, `core/virustotal.py` | verified |
| Seven CSV exporters | 7 `export_*_csv` functions, `core/reporter.py` | verified |
| Shared `_TEMP_DIRS` constant | 3 references, `core/hidden_data.py` | verified |
| 13,064 records, 100% agreement | Section 4 of this log | verified |
| Six injection profiles | Section 5 of this log | verified |
| 300-file corpus, 100% P/R | Section 6 of this log | verified |

No mismatch was found between the report and the archive.

## 12. Examiner status summary

| Area | Status | Evidence |
|---|---|---|
| Unit test suite | satisfied for non-GUI code | Section 3 — 123 discovered, 118 passed, 5 GUI tests skipped (no display); raw log in `evaluation/logs/` |
| $MFT external benchmark | fully satisfied | Section 4 — reproduced against `mft` 0.7.0, 100% agreement; raw log in `evaluation/logs/` |
| Six injection profiles | fully satisfied | Section 5 — reproduced, seed 20260930 |
| Detector corpus | fully satisfied | Section 6 — reproduced against libmagic 5.45 |
| Report exports | fully satisfied | Section 7 — all formats, escaping and failure path |
| Temp-directory regression | fully satisfied | Section 10 — shared constant plus test |
| Report-to-code match | fully satisfied | Section 11 — no mismatch |
| Package integrity | satisfied | Section 2 — per-file `SHA256SUMS.txt`; superseded archive digest recorded |
| GUI behaviour | not verifiable here | Section 8 — tests written, need Windows or Xvfb |
| Windows validation | not satisfied | Section 9 — procedure written, not run |
| VirusTotal live lookup | not satisfied | mock-only; needs an authorised key |
| Autopsy/FTK same-image benchmark | not satisfied | documentary comparison only |

Items marked not satisfied are stated as limitations in the report rather than
claimed. "Satisfied" here means the evidence in this file was produced by the
command shown, in the environment in Section 1, from the code in this archive;
it is not a claim about environments that were not tested.

## 13. Response to the 14 October 2026 feedback round

Each item below records the revised file or section, the code path where one
applies, the verifiable evidence, and an honest status. Items that require a
Windows host, an authorised API key or genuine historical records are listed
as outstanding rather than claimed.

| Feedback item | Action taken | Evidence | Status |
|---|---|---|---|
| [P1] Correct the test count | Replaced every "123 passing tests" claim in the dissertation with "123 discovered, 118 passed, five skipped" in the abstract, Chapter 5 results, Chapter 5 objective 5 and the Appendix B work-package table | `python -m unittest discover -s tests -t .` → `Ran 123 tests ... OK (skipped=5)`; raw log in `evaluation/logs/` | fully satisfied in the document |
| [P1] Reconcile archive SHA-256 | Section 2 of this file names the superseded `neehanth code.zip` digest `2fc77ad3…e63e3` explicitly and states that the final archive digest is published beside the archive in `ByteProbe_FINAL.zip.sha256`, because a ZIP cannot contain its own digest | Section 2; `SHA256SUMS.txt`; the `.sha256` sidecar shipped with the archive | fully satisfied |
| [P2] Focus Chapter 2 | Section 2.1.4 no longer surveys IoT, cloud, automotive, blockchain and OSINT. That breadth is now two sentences closing Section 2.1.3 (citations [31]–[40] retained), and the 2.1.4 slot is a critical synthesis of what the NTFS/timestomping literature settles and what it leaves open, linked to ByteProbe's design choices and to the measured misses in Chapter 4 | Dissertation §2.1.3 (final paragraph) and §2.1.4 | fully satisfied |
| [P2] Clean contents and referencing | Page numbering made continuous across the whole document (it previously restarted at 1 three times, so pages 1–8 were numbered twice); Chapter 4 subsections renumbered into page order (§4.1 Published Timestomping Comparison p.45, §4.2 Interpretation of the Detection Results p.47, §4.3 Related Works p.49); a broken "Section 4.1.1" cross-reference corrected; TOC, List of Figures and List of Tables regenerated | All 52 contents entries and all 24 figure/table rows re-verified line by line against the rendered PDF: zero mismatches | fully satisfied |
| [P2] Typography consistency | Two body paragraphs left at 10 pt restored to 12 pt; six figure captions normalised to the 10 pt caption size used by the rest | Document default is Calibri 12 pt; the only remaining 10 pt runs are table cells and figure captions | fully satisfied |
| [P2] Limitations and evaluation | Retained: §4.2 explains why profiles C, D and E are missed, why profile F's high-confidence rate collapses to 28.0% under bulk-copy suppression while any-confidence detection is 94.2%, why the 7.7% and 8.1% rates are triage load and not verified false-positive rates, and that both thresholds were fitted to the same sample | Dissertation §4.2 | fully satisfied |
| [P2] Final consistency audit | Every quantitative claim re-checked between the dissertation and this archive: 13,064 / 11,837 / 1,227 records, 94.2%, 28.0%, 41.4%, 7.7%, 8.1%, the 300-file corpus, the 7.2 entropy threshold, the two-second tolerance, the five-record bulk threshold and the seven risk weights | Section 11 and this round's re-check: no mismatch found | fully satisfied |
| [P1] Complete the declaration | Not actionable here — requires the author's signature and the university's process | Highlighted ACTION REQUIRED block retained on page 2 | outstanding |
| [P1] Finish Appendices B, C and D | Not actionable here — requires genuine dated supervision records, the final repository URL and commit, and the recorded screencast. No records were invented | Highlighted ACTION REQUIRED blocks retained in Appendices B, C and D | outstanding |
| [P1] Execute Windows validation W1–W7 | Not actionable here — no Windows/NTFS host available | `docs/WINDOWS_VALIDATION.md` procedure written and ready to run | outstanding |
| [P1] Reproduce independent MFT benchmark | Partly — the benchmark was reproduced in this environment against `mft` 0.7.0 (Section 4). An independent re-run by the examiner is still the stronger evidence | Section 4, raw log retained | partly satisfied |
| [P2] GUI smoke tests | Written and discovered, but they skip without a display. They must be run on Windows or under Xvfb before any "all passed" claim | `tests/test_gui_smoke.py`; Section 8 | outstanding |
| [P2] Live VirusTotal lookup | Not actionable here — no authorised key. The mock-only limitation is retained explicitly in the report. No key appears anywhere in this archive | Dissertation abstract and §4.3; `core/virustotal.py` | outstanding, limitation retained |
| [P2] Autopsy/Sleuth Kit same-evidence benchmark | Not actionable here. The documentary-only limitation is retained and no superiority claim is made | Dissertation §4.3 and §5.1 | outstanding, limitation retained |


## 15 October 2026 addendum — corrected GUI test harness

The above 14 October data is retained as historical evidence, not changed retroactively.
The GUI test harness was found to be unsuitable for unattended Xvfb runs: it
polled with `root.update()` rather than using `mainloop`, causing background
callback failures, and it invoked a modal reset confirmation without a stub.
Only the test harness was changed; the application modules were not silently
changed to make a passing result.

Independent rerun (Python 3.13.5, Linux/Xvfb):

- `xvfb-run -a python -m unittest tests.test_gui_smoke -v`: **5 passed**, zero skipped/failed; retained in `evaluation/logs/gui_smoke_xvfb_2026-10-15.log`.
- `xvfb-run -a python -m unittest discover -s tests -t . -v`: **123 passed**, zero skipped/failed; `evaluation/logs/unittest_xvfb_2026-10-15.log`.
- `python -m unittest discover -s tests -t . -v` without display: **118 passed, five skipped**, zero failed; `evaluation/logs/unittest_headless_2026-10-15.log`.
- `python evaluation/evaluate_detectors.py`: author-built **300-file** corpus reproduced; `evaluation/logs/detector_rerun_2026-10-15.log`.

The original independent `$MFT` comparison was **not rerun** in this
environment because the optional `mft` Python binding was unavailable, and the
13 MB public reference sample was not bundled. Treat its existing evaluation
log as prior retained evidence, not a result newly confirmed on 15 October.
No live Windows, real NSRL RDS, live VirusTotal, supervisor-contact, external
suite, GitHub push or screencast evidence is established by this update.
See `docs/RESUBMISSION_STATUS.md`.

## 16 October 2026 incremental scientific verification

- 128 tests passed under Linux/Xvfb, 0 failed/0 skipped; 128 discovered, 123 passed and 5 skipped without graphical display. Transcripts in `evaluation/logs/full_suite_2026-10-16.log` and `headless_suite_2026-10-16.log`.
- Reran detector corpus (`evaluation/logs/detectors_2026-10-16.log`), controlled timestamp stress test (`evaluation/logs/controlled_timestamps_2026-10-16.log`).
- Comparison with MFTECmd remains **unperformed**. Only two deliberately simulated CSV-reference cases validate the comparator itself. No Windows-host test, live VirusTotal lookup, real NSRL image, original screencast or GitHub push is claimed.
