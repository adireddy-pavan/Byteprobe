# Independent forensic benchmark protocol (not yet executed)

Goal: determine whether ByteProbe reproduces selected NTFS metadata fields and timestamp-anomaly evidence on an **additional, independent NTFS image**, rather than infer correctness from synthetic tests or a single publicly supplied MFT.

1. Obtain a legally distributable NTFS raw image or extracted `$MFT` with recorded provenance. Record acquisition URL/source, image SHA-256, operating-system generation if known, sample size, examiner, tool versions and timestamps. Do not claim evidence-chain verification absent a documented process.
2. Run ByteProbe read-only on an image copy. Export all records and the flagged anomalies. Retain console output and command/options used.
3. Run an independent established parser or suite (e.g. MFTECmd, The Sleuth Kit, Autopsy) on **the same artefact** with documented version and parsing options. Record what each tool actually supports; absence from a product manual does not prove missing functionality.
4. Align records using record number **and sequence number**, and treat path reconstruction separately from attribute extraction. Compare in-use/directory state, `$SI` timestamps, `$FN` timestamps, ADS names and full path where those fields are available in both outputs. Normalize UTC/timestamp precision before comparison; record unknown or unavailable fields as unavailable rather than equal.
5. Produce a table giving numerator/denominator of matched records and fields, exclusions, disagreements and representative cases. Preserve raw exports and a discrepancy CSV. Investigate differences rather than discarding them as invalid.
6. If testing timestomping, use a **second, independently defined** profile set and fresh images, with benign controls and ground truth. Report per-profile TP/FN and correctly labelled FP/TN only when ground truth is independently supported. Measure alert workload separately from error rates.
7. If feasible, report environment, throughput, CPU/memory and examination time on identical hardware, but never claim superiority without a controlled same-dataset experiment. Do not compare literature AUC or percentages with unrelated injected profile rates as if they were the same metric.

Deliverables: sample provenance, hashes, command transcript, versions, export files, field-level confusion/disagreement summary, limitations, and revised Chapter 4 text supported by those artefacts.

**Status:** protocol supplied; no new comparative data has been generated in this package.
