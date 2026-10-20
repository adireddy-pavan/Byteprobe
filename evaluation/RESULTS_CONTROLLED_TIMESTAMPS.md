# Controlled NTFS timestamp stress test

All observations below are on **author-built NTFS FILE records with assigned labels**. These results are reproducible checks of detector logic, not a real-world sensitivity, specificity, or attacker-prevalence estimate. The benign controls intentionally include copy/extraction and installer-like timestamp patterns. They are not representative random samples.

- 640 labelled synthetic records: 160 benign, 480 modified
- Profiles A–F each contain 80 records; benign controls include 40 each of identical, Modified-preserving copy, bulk-installer style (including five-file cohorts), and unique older-created extraction
- The same constructed records are scored at tolerance 0, 2 and 5 seconds and bulk threshold 3, 5 and 10 without choosing a winning threshold
- The Wilson 95% interval illustrates finite sample uncertainty within the constructed scenarios only; it cannot correct selection bias or confer external validity.

## Baseline policy (2 seconds tolerance, threshold 5)

| Ground-truth profile | N | Any-alert n (%) | High-alert n (%) | High-alert 95% Wilson interval |
|---|---:|---:|---:|---:|
| benign_identical | 40 | 0 (0.0%) | 0 (0.0%) | 0.0%–8.8% |
| benign_old_modified_copy | 40 | 0 (0.0%) | 0 (0.0%) | 0.0%–8.8% |
| benign_bulk_installer | 40 | 40 (100.0%) | 0 (0.0%) | 0.0%–8.8% |
| benign_unique_old_created | 40 | 40 (100.0%) | 40 (100.0%) | 91.2%–100.0% |
| A | 80 | 80 (100.0%) | 80 (100.0%) | 95.4%–100.0% |
| B | 80 | 80 (100.0%) | 80 (100.0%) | 95.4%–100.0% |
| C | 80 | 0 (0.0%) | 0 (0.0%) | 0.0%–4.6% |
| D | 80 | 0 (0.0%) | 0 (0.0%) | 0.0%–4.6% |
| E | 80 | 0 (0.0%) | 0 (0.0%) | 0.0%–4.6% |
| F | 80 | 80 (100.0%) | 20 (25.0%) | 16.8%–35.5% |

At high confidence: synthetic TP=180, FN=300, FP=40, TN=120; high-confidence synthetic recall 37.5% and specificity 75.0%. **These apply only to the generated scenarios; do not quote as real-world estimates.**

## Sensitivity to policy settings

| Tolerance (s) | Bulk threshold | High-alert benign / 160 | High-alert altered / 480 |
|---:|---:|---:|---:|
| 0 | 3 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 0 | 5 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 0 | 10 | 60 / 160 (37.5%) | 210 / 480 (43.8%) |
| 2 | 3 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 2 | 5 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 2 | 10 | 60 / 160 (37.5%) | 210 / 480 (43.8%) |
| 5 | 3 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 5 | 5 | 40 / 160 (25.0%) | 180 / 480 (37.5%) |
| 5 | 10 | 60 / 160 (37.5%) | 210 / 480 (43.8%) |

## Interpretation and limits

- Profile C changes only Modified; copying often preserves old Modified times. The current rule intentionally omits it to avoid naïve false alarms.
- Profile D forward-dates Created and Modified; a relational rule designed for backdating has no corroborating evidence to identify it.
- Profile E rewrites $SI and $FN consistently; these two attributes alone do not provide a trusted independent reference.
- Profile F copies a common Created timestamp on 30/80 attacks, one of five moderately shared donor timestamps on another 30, and unique donor timestamps on the remaining 20. The bulk-context downgrade suppresses many actual modified records together with benign installer lookalikes.
- Some legitimate copying/extraction scenarios are indistinguishable from backdating when only $SI and $FN are observed. A journal or independent timeline would be needed to adjudicate them.
- This is a retrospective developer-created stress test; no participants, fresh independent attackers, held-out volume, Windows host, or live tool benchmark was involved.
