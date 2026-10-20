# Final screencast checklist (not recorded in this package)

Record the **actual final commit and Windows build**; do not call a Linux/Xvfb demo Windows validation.

- Show application version, OS/Python version and Git commit identifier.
- Show all nine tabs by their actual names and explain the purpose of each.
- Run an authorized scan of reproducible benign demonstration files. Show the File Catalogue, Type Check and Integrity tabs and explain what SHA-256 verifies and why a known-good match is not an innocence verdict.
- Explain Shannon entropy and the 7.2 bits/byte heuristic; show a benign compressed high-entropy case and its interpretive limitation.
- Load a permitted `$MFT` sample; show `$SI` and `$FN` timestamps, flagged and unflagged records, confidence rules and the false negatives on coordinated modifications.
- Demonstrate Alternate Data Streams as available on the host, explaining any platform limits.
- Show VirusTotal's ready state. If no authorized live lookup occurred, say that only the mocked implementation was tested.
- Export the CSV/HTML/PDF reports as available, open the files, and explain audit metadata and evidence-handling limitations.
- Show code for hashing, entropy, timestamp rule(s) and a test command. Prefer real code to slides.
- Confirm the recording URL is viewable by an examiner without a login request; place the checked link in Appendix D.

**Status:** checklist only. No video was produced or verified here.
