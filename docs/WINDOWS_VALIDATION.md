# Windows validation procedure

This procedure covers the checks that cannot be performed on Linux or macOS, because
they depend on the Windows API or on a live NTFS volume. Run it on a Windows 10 or 11
machine or VM and record the result of each step in the table at the end. Where a step
cannot be completed, write "not completed" and the reason — do not leave a blank or
estimate a result.

## Setup

    python -V                     # 3.10 or newer required
    pip install -r requirements.txt
    pip install pywin32           # required for steps W2, W3 and W5
    python -m unittest discover -s tests -t .

After the 16 October laboratory-protocol extension, the current Linux/Xvfb run
reports 139 tests passed and zero skipped. Windows results remain unverified.
The installed Windows Python/dependencies and GUI availability can affect the actual
result. Record the actual counts, not the Linux counts as a substitute.

## W1 — GUI smoke tests execute

    python -m unittest tests.test_gui_smoke -v

Expected: five tests pass rather than skip. They verify that the window constructs,
that all nine tabs are present and selectable, that a background scan completes and
populates results, and that reset clears them.

## W2 — File ownership resolution

Scan any folder under `C:\Users\<name>\Documents`. In the File Catalogue tab, confirm
the Owner column shows `DOMAIN\user` or `MACHINE\user` rather than "N/A (Windows only)".
This exercises the `pywin32` path in `core/metadata.py`.

## W3 — NTFS attribute flags

In a Command Prompt:

    echo test > hidden_sample.txt
    attrib +H +S hidden_sample.txt

Scan that folder. Confirm the Hidden and System columns are both set for the file, and
that the Covert Data tab reports "Hidden + System attributes set".

## W4 — Alternate Data Stream discovery through the Windows API

    echo visible content > host.txt
    echo hidden payload > host.txt:secret.txt
    dir /r host.txt

Scan the folder. Confirm the Covert Data tab lists the stream `:secret.txt` for
`host.txt`. This exercises `FindFirstStreamW`/`FindNextStreamW` in
`core/hidden_data.py`, which returns an empty result on every non-Windows platform
and has therefore never been executed end to end before this step.

## W5 — Live volume $MFT access

Open an **Administrator** Command Prompt, start the tool, open the NTFS $MFT tab and
enter `\\.\C:` as the source, then parse. Confirm records are returned and that paths
resolve. If access is denied, record that and note the account used.

Also parse an extracted `$MFT` from the same machine for comparison if one is
available (for example via FTK Imager).

## W6 — Timestamp manipulation on a real file

Create a file, then in PowerShell:

    $f = Get-Item .\stomp_me.txt
    $f.CreationTime = "2019-01-01 09:00:00"

Parse the volume or an extracted `$MFT` and confirm the file appears in the $SI/$FN
findings. This corresponds to injection profile A, which was previously measured only
against synthetically modified records.

## W7 — Report exports on Windows

Generate CSV, HTML and PDF exports from the Export tab. Confirm all files open, the
audit block carries examiner, case, tool version, platform and scan times, and the
platform field names Windows.

## Results

Record the outcome of each step. Attach screenshots where a visual result is claimed.

| Step | Check | Result | Evidence |
|---|---|---|---|
| W1 | GUI smoke tests execute | | |
| W2 | Ownership resolves | | |
| W3 | Hidden/System attributes | | |
| W4 | ADS discovered via Windows API | | |
| W5 | Live volume $MFT access | | |
| W6 | Real timestamp manipulation detected | | |
| W7 | Exports on Windows | | |

Environment:

    Windows version :
    Python version  :
    pywin32 version :
    Date run        :


## W5 and W6 automated disposable-file verification (new)

In an elevated Windows 10/11 NTFS PowerShell session, run:

    python tools/run_windows_w5_w6_lab.py --confirm-disposable-test --output windows_evidence/W5_W6

This touches only a newly-created disposable specimen in the system temp directory, reads the NTFS live volume read-only and exports authentic before-and-after `$SI/$FN` timestamps in JSON. The script refuses Linux, a non-NTFS drive, missing administrative rights, or missing explicit consent. See `docs/THREE_TECHNICAL_VALIDATIONS_EXACT_STEPS.md`. It does **not** mean W5/W6 are already passed.
