# ByteProbe: the three remaining technical validation tasks

This file is a **procedure**, not a statement that the pending tasks have passed. Prior 131-test Linux/Xvfb run is independent of native Windows validation. Do not edit the dissertation to say W5/W6 or MFTECmd passed until authentic output exists.

## A — Native Windows 10/11 validation (W1–W7)

**Manual prerequisite (unavoidable):** an authorised Windows 10/11 NTFS computer or VM with Python 3.10+, pywin32 and ReportLab; Administrator rights are needed for the live-volume lab. Only use a computer/VM the student is authorised to inspect, never an evidential disk. Back up before running unfamiliar software. The W5/W6 script changes only a disposable specimen file inside the Windows temp directory and reads the live volume read-only. External scripts must be reviewed before execution.

1. Extract this ZIP to a Windows folder; open an elevated PowerShell terminal in `ByteProbe`.
2. Install dependencies (internet required for install, not for forensic operation):

   ```powershell
   py -3 -m pip install -r requirements.txt pywin32 reportlab
   ```
3. Execute full unit tests and capture authentic transcript:

   ```powershell
   New-Item -ItemType Directory -Force -Path windows_evidence | Out-Null
   py -3 -m unittest discover -s tests -t . -v *> windows_evidence\unit_suite.txt
   ```
4. Execute native file metadata, ADS and export checks; this outputs `windows_validation.json` plus evidence files:

   ```powershell
   py -3 tools\run_windows_checks.py --output windows_evidence\W1_W4_W7
   ```
5. With the same elevated session, explicitly authorise a **disposable one-file** lab for live MFT and CreationTime manipulation:

   ```powershell
   py -3 tools\run_windows_w5_w6_lab.py --confirm-disposable-test --output windows_evidence\W5_W6
   ```

   On success, `W5_W6_real_windows_results.json` contains the record/sequence, raw before/after $SI and $FN Created values, anomaly text and authentic OS identity. If the temp drive is not NTFS, pass `--test-root C:\A_Dedicated_Existing_NTFS_Test_Folder`. The script must **not** be run on forensic evidence, and it refuses Linux or non-elevated use. A failure is a finding to investigate, not grounds to edit the JSON.
6. The examiner should inspect the W1–W7 evidence and GUI screenshots directly on Windows. A CI runner alone cannot substitute for an approved real-volume lab. Timestamp W6 uses only a disposable Created-time backdate (profile A), not all six independent real-world attack profiles.

**Deliver back:** the complete `windows_evidence` folder and a screenshot of the active ByteProbe `$MFT` tab from the same host, with the date, environment and commit/release identifier.

## B — Independent same-evidence comparison with MFTECmd

**Manual prerequisite (unavoidable unless a real reference export is uploaded):** a second lawfully sourced, independently created `$MFT` sample from an authorised NTFS Windows image; the byte-for-byte same extracted file must be processed by ByteProbe and MFTECmd. A new name for the same old dataset is not a second independent sample.

1. Get the official MFTECmd software from its maintainer and record release/version: https://github.com/EricZimmerman/MFTECmd. Do not invent a tool version.
2. Preserve the original extracted `$MFT` as `dataset_B_MFT` and record SHA-256:

   ```powershell
   Get-FileHash .\dataset_B_MFT -Algorithm SHA256
   ```
3. Execute MFTECmd on the exact extracted file (adjust the executable path):

   ```powershell
   .\MFTECmd.exe -f .\dataset_B_MFT --csv .\reference --csvf reference.csv --at
   ```
4. From ByteProbe root run the independent CSV field comparator:

   ```powershell
   py -3 evaluation\compare_mftecmd.py .\dataset_B_MFT .\reference\reference.csv --out .\evaluation\comparison_B
   ```
5. Review `summary.json`, `summary.md`, `unmatched_record_keys.csv`, and `discrepancies.csv`. The matching key is (entry, sequence) rather than file name alone. Cite total counts, missing records, ambiguous names, excluded fields, and disagreements. Timestamp comparison truncates the seventh 100ns digit; explicit timezone offsets are normalized to UTC. Do not say 100% if there are unmatched records or excluded fields.
6. Repeat using the original first public sample as dataset A **if** its bytes and an independently generated MFTECmd CSV are available; its previously published Rust parser evaluation is supporting evidence but is not a completed MFTECmd comparison.

**Deliver back:** binary `dataset_B_MFT` (or accessible authorised source), MFTECmd CSV, MFTECmd actual command transcript/version, input SHA-256 and the comparison output folder. A ZIP containing just the Python script is **not** a completed experiment.

## C — Detector reliability and falsifiability

**Already reproducible locally:** the 640-case author-created labelled stress test, six synthetic timestamp profiles A–F, four benign-lookalike categories, nine policy variants, and 131 passing Linux/Xvfb tests (before this validation extension).

**Current evidence:** in the constructed cases, high-confidence sensitivity is 180/480 (37.5%), and high-confidence alerts occur on 40/160 benign controls (25%). C/D/E have zero high-confidence detections; the detector has no independent historical evidence to distinguish coordinated $SI+$FN rewriting from unmodified records. These results cannot be promoted into a real-world precision, recall or false-positive claim.

**Real next experiment (manual evidence required):** on a disposable Windows NTFS volume, record a baseline extracted `$MFT`, exercise A/B/C/D/F with explicit scripts and timestamps, acquire a second `$MFT`, use an independent tool to verify which fields really changed, and repeat with common benign activities such as copy, extraction and software installation. E requires low-level modification of both attributes; do not attempt that on a real host or claim it can be detected by `$SI/$FN` alone. Use an approved forensic lab/test image instead. Assign ground truth from witnessed operations, not from ByteProbe's alerts. Test threshold settings against a **held-out** evidence source rather than optimising and reporting on the same one.

**Acceptable scientific outcome:** more verified misses with well-defined limitations are better than fabricated high accuracy. If detector improvements are made, rerun every profile and quantify BOTH attack recall and benign alert cost.

## Examiner evidence gate

Only mark a task **Verified** if exact commands, dated output, dataset hashes, OS and tool versions, errors, and discrepancies are retained. Otherwise mark **Prepared**, **Not Tested** or **Partially Evaluated**. Completing these checks improves the academic validity of the project; it does not guarantee a particular university grade.
