# Raw run logs

These are the unedited console transcripts of the verification runs quoted in
`EVIDENCE.md`. They are kept so that a marker can compare the summarised
tables in the dissertation against the output the scripts actually produced.

| Log | Produced by | Date |
|---|---|---|
| `mft_benchmark_2026-10-14.log` | `python evaluation/evaluate_mft.py` | 14 October 2026 |
| `unittest_2026-10-14.log` | `python -m unittest discover -s tests -t . -v` | 14 October 2026 |

`unittest_2026-10-14.log` shows the full result for the tested environment:
123 tests discovered, 118 passed, 5 skipped. The five skips are the GUI smoke
tests in `tests/test_gui_smoke.py`, which `unittest` skips automatically when
no display is attached (headless Linux container). On a Windows or Linux host
with a display they execute; see `docs/WINDOWS_VALIDATION.md` step W6.

The $MFT sample itself is not redistributed in this archive. The log records
its SHA-256 so the same file can be re-fetched and verified; the script
downloads it on first run.
