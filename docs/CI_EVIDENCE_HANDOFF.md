# CI and authentic-evidence handoff (16 October 2026)

The project now has `.github/workflows/windows-validation.yml`. On *GitHub-hosted Windows* runners, it will attempt to execute all Python tests including GUI smoke tests, and actual disposable host checks W1-W4 and W7. An Actions job succeeding **does not** perform W5/W6 (live NTFS $MFT access and on-volume timestomping) and does not establish all forensic functionality.

To use: publish the exact source to an authorized GitHub repository, choose the Actions tab, and run `ByteProbe Windows verification (bounded scope)` via `workflow_dispatch`. Download the workflow's `byteprobe-windows-evidence-...` artifact and retain the actual logs. Record the actual commit SHA. If the job fails, fix it first; a workflow file is not validation evidence.

For W5/W6, conduct the dated examination on an approved disposable Windows NTFS volume, preserve both GUI and independent-MFT screenshots/exports with timestamps, and record PASS/FAIL/NOT TESTED. Do not tamper with any real case or personal files.

For independent benchmarking, obtain a separately sourced suitable NTFS sample, then run MFTECmd and `evaluation/compare_mftecmd.py` against the SAME extracted `$MFT`. Verify source details, SHA-256 of input, CSV and exact MFTECmd build. Do not substitute generated test fixtures or the original XP sample for the requested second independent source.

For repository proof record online SHA and working URL. For screencast record the **actual final tool**, not still slides; identify whether Windows or Linux, show the result and explain hash and entropy. Any Linux demo bundled by ChatGPT is supplementary teaching material and NOT the student's final Windows screencast.

For the declaration and supervision records, obtain genuine signed form and real records from the student; if none exists, disclose that honestly. Neither source code nor automated PDF generation can make a retrospective signature or supervisor approval genuine.

Run `python tools/audit_submission_evidence.py --evidence evidence_external --out evidence_audit.json` to list received items. This audits presence and obvious contradictions; a professor must still review authenticity and scientific sufficiency.
