# 16 October 2026 Technical verification addendum

New, independently executed on this Linux/Xvfb working environment:

- `xvfb-run -a python -m unittest discover -s tests -t . -v`: **139 tests passed; zero failures; zero skips** (`evaluation/logs/unittest_139_xvfb_16Oct2026.log`).
- Headless suite: **134 tests passed and five skipped** because Tkinter has no display (`evaluation/logs/unittest_headless_139_16Oct2026.log`).
- Synthetic adversarial experiment rerun: 640 generated labelled records, TP=180, FN=300, FP=40, TN=120 for high-confidence events in its deliberately adversarial constructed cases. No real-world precision or false-positive accuracy claim.
- Three guard/summary tests for the new opt-in Windows W5/W6 lab and five timestamp-comparator tests were added (131 + 8 = 139). These validate helper logic but do not substitute for real Windows execution or an MFTECmd export.
- Independent benchmark comparator fixed to handle timezone offsets in `DateTimeOffset` strings without accidentally stripping the timezone digits into the fractional-second component; it now exports unmatched record keys separately. **No real MFTECmd run was performed.**
- Opt-in W5/W6 lab runner prepared and explicitly tested to refuse a non-Windows host (`exit 3`). **No Windows lab was performed in this environment.**

Required before replacing the dissertation's 'pending validation' statement:
1. Execute W1-W7 on an authorised Windows NTFS machine, preserve run output and actual OS/version.
2. Supply the independently sourced dataset B and its MFTECmd CSV from **the same file**; preserve SHA-256 and tool version.
3. Have a separate person or lab validate a held-out dataset or a prospective set of witnessed Windows operations, and record ground truth before comparing detector outputs.

The prior Linux GUI recording is **not** a Windows validation screencast.
