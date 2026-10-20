# External validation and submission evidence: tasks that remain genuinely unverified

**Status: not complete as of 16 October 2026.** No Windows machine, external forensic parser output, repository credentials, supervisor correspondence, or video-recording environment was available for this correction. Do not tick these items off merely because this protocol exists.

## A. Windows host (W1–W7)

1. Use an isolated Windows 10/11 NTFS VM with sufficient permissions; record Windows build, Python version, pywin32 and ReportLab versions, machine/timezone and date. Preserve a screenshot of the desktop version information.
2. Run `python tools/run_windows_checks.py --output windows_evidence` as a standard user. This automates the disposable-file tests W1–W4 and W7. It records a JSON manifest and supporting exported files. It refuses to run outside Windows. It **does not** perform live disk parsing or timestomping.
3. Complete W5 on an authorized expendable Windows NTFS test volume, using Administrator only where needed. Capture the on-screen `$MFT` parser output and a same-volume extracted `$MFT` file. Record access denials and whether the file was open in another process.
4. Complete W6 on that disposable volume: create a test file, record its before-state and volume details, use the PowerShell CreationTime change in `WINDOWS_VALIDATION.md`, capture after-state from an independently exported `$MFT`, and compare the `$SI` and `$FN` timestamps. Do not alter any non-test files.
5. Keep a result of PASS/FAIL/NOT TESTED for each W1–W7. If failures occur, fix and rerun while retaining both logs. Unpassed tests cannot be described as passed.

## B. Genuine independently parsed NTFS sample

Obtain an independent second sample with verifiable provenance, ideally a Windows 10/11-created NTFS volume. Public possibilities include [NIST CFReDS](https://cfreds.nist.gov/) and [Maxim Suhanov's NTFS sample repository](https://github.com/msuhanov/ntfs-samples). The suitability of the selected image must be checked; not every CFReDS image is NTFS or has the same task scope.

1. Use the **same extracted `$MFT` byte-for-byte** in ByteProbe and a separately installed independent reference tool, such as [MFTECmd](https://github.com/EricZimmerman/MFTECmd). Record source URL, origin documentation, license, filename, SHA-256, host/tool versions and export commands. Preserve evidence of how the NTFS image was converted or its MFT extracted.
2. Example for MFTECmd, adapted to the installed version's `--help`:
   ```
   MFTECmd.exe -f "C:\\evidence\\$MFT" --csv "C:\\evidence\\ref" --csvf "reference.csv" --at
   python evaluation/compare_mftecmd.py "C:\\evidence\\$MFT" "C:\\evidence\\ref\\reference.csv" --out "C:\\evidence\\comparison"
   ```
   The script matches **EntryNumber + SequenceNumber**, compares common metadata and both timestamp sets at microsecond resolution, and exports `summary.json`, `summary.md` and `discrepancies.csv`. Verify MFTECmd's timestamp timezone and whether flags/blank dates are comparable. Do not count excluded fields as agreements. MFTECmd emits additional metadata not parsed by ByteProbe; this is not an equivalence study of the entire suites.
3. Investigate each representative discrepancy. Include n/N for each field, excluded field counts, records missing in either output, and relevant screenshots. Only then add the verified data to Chapter 4.
4. If using Autopsy instead, document the Autopsy+Sleuth Kit versions, exact source image, ingest options and metadata exports; **do not** present documentary comparison as a run.

## C. Assessment artefacts to finish personally

- **GitHub**: push the exact ZIP source contents to the approved public repository, not the previous eight-tab snapshot. Verify remote repository file tree and log the actual immutable commit SHA and URL. Confirm that test logs, benchmark scripts and README are present. See `GITHUB_PUBLISH.md`.
- **Screencast**: film the actual final Windows application; demonstrate all nine tabs, MFT, timestamp findings, integrity/hashsets, entropy, VirusTotal *ready/mock vs live* status, exports, code for SHA-256 and entropy, and Windows verification status. Capture the link only once the video exists and playback is verified.
- **Supervision**: attach authentic contemporaneous emails, meeting notes, or recorded feedback; state clearly if none are retained. Do not manufacture a log.
- **Declaration**: the student must verify university wording, sign/date it, and remove remaining instructions before submission.

## D. Research quality warning

The new `evaluation/evaluate_controlled_timestamps.py` experiment exposes actual **known-label synthetic false positives** and misses, unlike the older sample's **unlabelled alert rates**. Synthetic scenario-specific confusion counts cannot establish generalization or a true-world 90+ mark. A new independent or blinded, untouched test image is still the most consequential missing evidence.
