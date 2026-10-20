# Verified additions on 16 October 2026

Changes are described for reproducibility, not presented as independent validation:

- Added `evaluation/evaluate_controlled_timestamps.py`: 640 author-constructed NTFS records (160 benign, 480 altered); six injected tampering scenarios, four benign-lookalike categories, a 3×3 sensitivity analysis of the tolerated ordering gap and bulk confidence cutoff, and Wilson intervals. Creates `evaluation/RESULTS_CONTROLLED_TIMESTAMPS.md` and `controlled_timestamps.csv`.
- Added `evaluation/compare_mftecmd.py`: comparison harness for separately generated MFTECmd CSV on an identical extracted `$MFT`; joins on entry number+sequence, distinguishes disagreement/exclusion, writes CSV and JSON evidence. **Tested with mock CSV only; actual MFTECmd has not been executed.**
- Added `tools/run_windows_checks.py`: safe Windows-only verification runner for disposable W1–W4 and W7 checks. **Not run on Windows.** W5/W6 remain manual by design.
- Corrected the earlier evaluation script's scientifically invalid use of *false-positive rate* on records with unknown tampering status. It now calls this an *alert rate*.
- Clarified report output's audit metadata as not constituting an acquisition chain of custody.
- Added regression tests for the comparison harness, ambiguous CSV records and controlled robustness experiment, and reran the complete test suite under Linux/Xvfb.

Sources/protocols: `docs/EXTERNAL_VALIDATION_AND_SUBMISSION.md`, `docs/WINDOWS_VALIDATION.md`, and `docs/GITHUB_PUBLISH.md`.
