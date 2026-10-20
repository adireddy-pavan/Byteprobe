# Screenshots

`current/` holds the screenshots of **this version** of ByteProbe. They were produced by
`tools/capture_screenshots.py`, which runs the real GUI code on a demo evidence folder and saves the live window.

Conditions, stated so the screenshots are not over-read:

- Captured on **Linux (Ubuntu, Python 3.12) under a virtual display (Xvfb)**, not on Windows.
  Fonts and window chrome therefore differ from a Windows or macOS desktop.
- Windows-only features (NTFS ADS through `FindFirstStreamW`, owner lookup through pywin32) do not appear.
  The Windows header warning ("non-Windows: 'created' = inode-change time") is visible for the same reason.
- The `$MFT` tab shows the public sample `$MFT` (13,402,112 bytes) from the `mft` project, not a live volume.
- The VirusTotal tab is in its ready state. No live lookup was made.
- The earlier June 2026 screenshots were removed because they showed the previous version.

To regenerate on any machine with a display (a real desktop or Xvfb):

```bash
python evaluation/evaluate_mft.py        # downloads the sample $MFT once
xvfb-run -a -s "-screen 0 1500x950x24" python tools/capture_screenshots.py
```

(On a desktop, run `python tools/capture_screenshots.py` directly. It needs ImageMagick's `import` command for the capture.)
