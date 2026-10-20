# Test data

Real MFT records taken from Windows NTFS volumes, from the `samples/` directory of
the independent `mft` parser by Omer Ben-Amram:
https://github.com/omerbenamram/mft (licensed Apache-2.0).

| File | What it contains |
|---|---|
| `entry_single_file` | In-use file `test_cfuncs.py`, with Win32 and DOS 8.3 `$FILE_NAME`s and a non-resident `$DATA`. `$SI` Created (2008) is earlier than `$FN` Created (2009). |
| `entry_102130_fixup_issue` | The `Application Data` directory. Its first 512-byte sector fails the update-sequence (fixup) check, so it is a genuinely torn record. |
| `entry_data_run_at_offset` | An extension record (base record 57676) that holds the `$J` stream of `$UsnJrnl`: a 2 GB, sparse, heavily fragmented non-resident ADS. |

The expected values in `tests/test_mft.py` were cross-checked against that
project's Python bindings (`pip install mft`), which parse the records independently.

The full 13 MB `$MFT` that `evaluation/evaluate_mft.py` uses comes from the same repository. The
script downloads it on first run, so it is not bundled here.
