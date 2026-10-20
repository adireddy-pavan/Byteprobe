# Authentic final ByteProbe screencast: Windows recording instructions

## Current evidence
A nine-second **real Linux/Xvfb GUI recording** was made on 16 October 2026 from `tools/capture_screenshots.py`. It shows the synthetic 12-file case and actual tab interactions, without narration. It is labelled `NOT WINDOWS VALIDATION`; it does **not** show live MFT parsing, ADS or Windows ownership resolution and cannot be submitted as a complete Windows screencast.

## Final 4–6-minute Windows recording (student must capture on own authorised NTFS VM)

Before pressing Record: show `winver`, Python version, source folder/repository commit SHA, the W1–W7 evidence report and no personal/privileged evidence. Use a non-sensitive test volume. Do not show API keys. Then narrate:

1. (0:00–0:35) Project title, examiner use case and explicit limitation: prioritisation, not conclusive maliciousness or acquisition.
2. (0:35–1:20) File Catalogue, signatures and hashing: scan a disposable folder; show a renamed header and SHA-256; explain digest integrity and reference-set matching with legitimate known-good entries.
3. (1:20–2:00) Hidden/System flags and ADS on the Windows NTFS volume; show the command that created the disposable ADS, rather than representing synthetic Linux data as a native Windows result.
4. (2:00–2:45) Real extracted `$MFT` and `$SI/$FN` findings: identify the sample's source, SHA-256, field output, benign caveats, and the genuinely executed timestomp case. If not validated, explicitly say `not tested` on camera.
5. (2:45–3:20) Entropy Map: show a compressed/encrypted-looking test file and explain Shannon entropy; do not equate high entropy with malware.
6. (3:20–3:45) VirusTotal: show only mock/test readiness unless an actual authorized API lookup was done; do not expose secrets or upload files.
7. (3:45–4:20) Export CSV/HTML/PDF and case metadata; explain chain-of-custody limits.
8. (4:20–5:10) Show code for SHA-256, Shannon entropy and SI/FN detector, a fresh unit-test command, the actual Windows verification results and independently generated MFTECmd CSV comparison if performed.
9. (5:10–5:35) Discuss three missed synthetic injection profiles and legitimate-alert trade-off, then show repository commit SHA and clearly state remaining limitations.

Record screen and spoken explanation in one genuine continuous Windows capture; editing to remove accidental secrets is acceptable if disclosed. Before submission, verify the hosted link works in a private/incognito browser and cite its URL in Appendix D. Do not substitute the current Linux supplementary clip or AI voice-over for evidence of a personally performed Windows test.
