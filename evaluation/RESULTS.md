# ByteProbe NTFS evaluation results

- Sample: `MFT`, 13,402,112 bytes, SHA-256 `c78f4968345b70783fbf6573d86c4bf300295ae26ddde4033dd1037b802e13c1`
- Source: https://raw.githubusercontent.com/omerbenamram/mft/master/samples/MFT
- Python 3.13.7, random seed 20260930

ByteProbe parsed **13,064** base records (11,837 in use, 1,227 deleted) in **0.23 s**; 0 record(s) failed the fixup check; 10 record(s) carry named $DATA (ADS).

## 1. Parser accuracy compared with an independent reference implementation

Reference: `mft` crate (Rust) Python bindings, 0.66 s. Records compared: 13,064 (reference-only: none, ByteProbe-only: none).

| Field | Agreeing / compared | Agreement |
|---|---|---|
| Allocated (in-use) flag | 13,064 / 13,064 | 100.0% |
| Directory flag | 13,064 / 13,064 | 100.0% |
| $SI timestamps (all four) | 13,064 / 13,064 | 100.0% |
| $FILE_NAME set (name, parent, 4 timestamps) | 13,064 / 13,064 | 100.0% |
| ADS names | 13,064 / 13,064 | 100.0% |
| Full path (in-use records) | 11,833 / 11,833 | 100.0% |

## 2. Alerts on unmodified real data

No controlled tampering was introduced in this image, so these alerts measure the observed triage workload on this sample. The sample has no independently established per-record tampering ground truth, so no false-positive rate can be inferred. Measured on 11,833 in-use records that have both $SI and $FN:

| Method | Records flagged |
|---|---|
| os.stat baseline (modified < created) | 2,346 (19.8%) |
| $SI/$FN rules, no tolerance, no context | 5,255 (44.4%) |
| $SI/$FN rules, 2 s tolerance (all confidences) | 4,904 (41.4%) |
| $SI/$FN rules, **high confidence only** (Created value shared by < 5 records) | **917 (7.7%)** |

The dominant benign cause is Windows setup and other installers. They stamp $SI Created and Modified with the package build time in whole seconds (e.g. `2006-02-28 12:00:00` on thousands of XP files), while $FN records the actual install time. This is exactly the pattern a whole-second timestomp leaves. The tolerance and high-confidence settings were chosen after inspecting this data set, so the high-confidence rate is optimistic for other images.

Findings by rule (tolerance applied, all confidences):

| Rule | Records |
|---|---|
| $SI Created has zero sub-second precision | 4,841 |
| $SI Created earlier than $FN Created | 4,312 |
| $SI MFT-changed earlier than $FN MFT-changed | 45 |

Where the high-confidence alerts are (top-level folders):

- `\Program Files\AIM6`: 700
- `\DRIVERS\Win`: 102
- `\WINDOWS\system32`: 73
- `\Documents and Settings\Donald Blake`: 17
- `\Program Files\Common Files`: 9
- `\WINDOWS\SoftwareDistribution`: 4
- `\WINDOWS\Help`: 3
- `\WINDOWS\repair`: 2

## 3. Controlled timestomping injection

500 in-use files were sampled from 3,700 files that neither method flags. Each attack profile rewrites the $SI bytes of those records in a copy of the $MFT. The copy is then re-parsed. "Landed" confirms that ByteProbe reads back exactly the injected values; "Reference agrees" confirms that the independent parser sees the same values.

Detection rate on the tampered files:

| Profile | Attack | Landed | Reference agrees | $SI/$FN (any) | $SI/$FN (high confidence) | os.stat baseline |
|---|---|---|---|---|---|---|
| A | Backdate Created+Modified to a whole-second date (timestomp.exe / PowerShell `.CreationTime = "2019-01-01 09:00"`) | 500/500 | 500/500 | 100.0% | **100.0%** | 44.8% |
| B | Backdate all four $SI values with random sub-second ticks (careful tool, keeps 100 ns precision) | 500/500 | 500/500 | 100.0% | **100.0%** | 52.2% |
| C | Change only $SI Modified to an earlier precise time | 500/500 | 500/500 | 0.0% | **0.0%** | 100.0% |
| D | Forward-date Created/Modified to a later precise time (hide a file among newer ones) | 500/500 | 500/500 | 0.0% | **0.0%** | 49.6% |
| E | Whole-second backdate of $SI AND $FN together (SetMACE-style / rename trick copies $SI into $FN) | 500/500 | 500/500 | 0.0% | **0.0%** | 0.0% |
| F | Copy all four $SI values from a random \\WINDOWS\\system32 file (`timestomp -f`, `touch -r`) | 500/500 | 500/500 | 94.2% | **28.0%** | 29.2% |

Alert rate on the 11,333 non-injected in-use records of the same volume: $SI/$FN any = 43.3%, $SI/$FN high confidence = **8.1%**, os.stat baseline = 20.7%.


Interpretation:
- **A and B** are the attacks the report describes: back-dating a file with a user-mode API. The $SI/$FN comparison catches them because $FN still holds the real creation time. The baseline only fires if the attacker happens to set Modified earlier than Created.
- **C** (only Modified moved earlier) is invisible to the $SI/$FN detector by design. Modified is excluded from the ordering rule because copying or extracting a file legitimately preserves an old Modified time. The os.stat baseline catches C, but it flags approximately 20% of non-injected records in this sample (not a verified false-positive rate), so the two checks are complementary. That is why ByteProbe keeps both.
- **D** (forward-dating) and **E** (where $FN is also rewritten, e.g. SetMACE or a rename after stomping) defeat the $SI/$FN comparison. Detecting them needs $UsnJrnl/$LogFile correlation, which ByteProbe does not implement.
- **F** (copying timestamps from a system file) is still caught by the ordering rule, because the donor is older than the target's $FN. However, it is usually downgraded to low confidence, because the copied value is a bulk installer timestamp. That is the price of the noise suppression, and an attacker who knows the rule can exploit it.
- Candidate files were chosen from those that neither method flagged beforehand, so detections come from the injection alone. The baseline figure for A/B/D depends on whether the random dates happen to put Modified before Created.

