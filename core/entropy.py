"""Shannon entropy analysis -- detects encrypted/packed/compressed files."""

import math
from collections import Counter
from dataclasses import dataclass

CHUNK = 1 << 16  # 64 KB read buffer
BLOCK = 4096         # window for the per-region entropy scan
MIN_BLOCK = 256      # a shorter block cannot reach 7.2 bits (max = log2(n))
HIGH = 7.2


@dataclass
class EntropyResult:
    path: str
    entropy: float        # 0.0 (uniform) to 8.0 (perfectly random)
    is_high_entropy: bool  # True when entropy > 7.2
    note: str
    max_block_entropy: float = 0.0     # highest entropy of any 4 KB block
    high_blocks: int = 0               # number of 4 KB blocks above 7.5 bits
    has_high_entropy_region: bool = False  # packed/encrypted part inside a normal file


def _shannon(counts, total: int) -> float:
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def compute_entropy(path: str) -> EntropyResult:
    # Counter.update tallies the byte values of each chunk in C, avoiding a
    # Python-level loop over every byte.
    counts = Counter()
    total = 0
    max_block = 0.0
    high_blocks = 0
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                counts.update(chunk)
                total += len(chunk)
                # Per-block scan: a file that is mostly normal but holds a
                # packed or encrypted section has a low whole-file entropy.
                for i in range(0, len(chunk), BLOCK):
                    block = chunk[i:i + BLOCK]
                    if len(block) < MIN_BLOCK:
                        continue
                    e = _shannon(Counter(block), len(block))
                    max_block = max(max_block, e)
                    if e > 7.5:
                        high_blocks += 1
    except (OSError, PermissionError):
        return EntropyResult(path, 0.0, False, "Could not read file")
    if total == 0:
        return EntropyResult(path, 0.0, False, "Empty file")
    entropy = _shannon(counts, total)
    high = entropy > HIGH
    # Four or more blocks (16 KB) above 7.5 bits = a real region, not noise.
    region = (not high) and high_blocks >= 4
    if high:
        note = "Likely encrypted/packed/compressed"
    elif region:
        note = (f"Normal overall, but {high_blocks} blocks of {BLOCK} bytes are "
                "high-entropy (possible packed/encrypted section)")
    else:
        note = "Normal entropy"
    return EntropyResult(path=path, entropy=round(entropy, 4), is_high_entropy=high,
                         note=note, max_block_entropy=round(max_block, 4),
                         high_blocks=high_blocks, has_high_entropy_region=region)


def analyze_all(paths: list[str], progress_cb=None) -> list[EntropyResult]:
    results = []
    for path in paths:
        results.append(compute_entropy(path))
        if progress_cb:
            progress_cb(path)
    return results
