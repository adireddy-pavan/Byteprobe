# Resubmission verification status (15 October 2026)

This status distinguishes reproducible evidence from work requiring an examiner-controlled environment or the student's own records. It is **not** a certification, claim of final submission readiness, or a predicted mark.

## Corrected and independently rerun in the supplied Linux environment

1. GUI smoke-test harness: `tests/test_gui_smoke.py` now drives `Tk.mainloop()` while the scan worker schedules UI updates. Its reset test patches the modal yes/no confirmation, and its background-scan test has a 20-second watchdog, checks actual result tables, and creates/cleans its own temporary input directory.
2. Full test suite, virtual display: `xvfb-run -a python -m unittest discover -s tests -t . -v` completed **123 passed, 0 failed, 0 skipped** (log: `evaluation/logs/unittest_xvfb_2026-10-15.log`).
3. Full test suite, no display: `python -m unittest discover -s tests -t . -v` completed **118 passed, 0 failed, 5 skipped**, as expected (log: `evaluation/logs/unittest_headless_2026-10-15.log`).
4. Synthetic detector evaluation: `python evaluation/evaluate_detectors.py` completed and reproduced the reported figures on author-built data (log: `evaluation/logs/detector_rerun_2026-10-15.log`). These results do NOT establish generalization to independent forensic data.

## Verified defect and remedy

**Before:** Running the unmodified GUI tests under Xvfb timed out. The scan worker called `root.after(...)` while the main thread performed repeated `root.update()` calls rather than running Tk's `mainloop`, causing `RuntimeError: main thread is not in main loop`. The reset test invoked an unmocked modal `askyesno`, blocking unattended runs.

**After:** Scan test enters `mainloop`, completion is detected via a Tk scheduled poll, watchdog cancels hung runs, reset dialogue is mocked, and each test has a new application instance. Both GUI-only and full-suite Xvfb runs now complete without a hang. This addresses a *test-harness defect*, not proof that the Windows runtime has been validated.

## Still requires independent completion

| Item | Status / real evidence required |
|---|---|
| W1–W7 actual Windows validation | **NOT RUN** in this environment. Student must execute and document using `docs/WINDOWS_VALIDATION.md`; attach screenshots and platform/version data. |
| Independent second NTFS sample and Autopsy/FTK/MFTECmd comparison | **NOT RUN**. See `docs/INDEPENDENT_BENCHMARK_PROTOCOL.md`. Public sample results from the earlier run are retained; not newly reproduced here. |
| Real NSRL RDS subset | **NOT RUN**. Unit tests exercise synthetic CSV/SQLite formats only. |
| Live VirusTotal lookup | **NOT RUN**. Unit tests use mocks. Only use authorized benign hashes and protect the API key. |
| GitHub state/commit and repository-vs-ZIP equivalence | **NOT VERIFIED**. The student must push, capture commit SHA, compare file manifests, and verify access. |
| Final screencast accessibility and feature coverage | **NOT VERIFIED**. Follow `docs/SCREENCAST_CHECKLIST.md`. |
| Supervisor meetings/progress records | **NOT PROVIDED**. Student must supply genuinely dated artefacts; never fabricate. |
| Independent validation of detector thresholds or verified false-positive rates | **NOT RUN**. Current alert rates without independently established ground truth are not false-positive rates. |

The report should continue to label the 0% detection profiles and low-confidence outcomes as real limitations, not quietly rebrand them as resolved.

## 16 October 2026 additional evaluation (subsequent to this status note)

The source tree was expanded to **128** discovered tests. In the verified Linux/Xvfb run, all 128 passed with none skipped or failed (`evaluation/logs/full_suite_2026-10-16.log`); in a headless run, 123 passed and five GUI tests skipped (`evaluation/logs/headless_suite_2026-10-16.log`).

A new 640-record synthetic benchmark checks six manipulated profiles and benign lookalikes under nine threshold combinations. It exposes residual misses and detection-versus-alert trade-offs (`evaluation/RESULTS_CONTROLLED_TIMESTAMPS.md`). It is developer-constructed and does not establish real-world error rates. The MFTECmd export-comparison harness is exercised **only against mock CSV fixtures**. The Windows runner is created but remains **untested on Windows**; GitHub push, supervision proof and final screencast remain unverified. See `docs/EXTERNAL_VALIDATION_AND_SUBMISSION.md`.
