"""Shannon entropy based detection for random-looking strings."""

import math
import re
from collections import Counter

# Short strings do not give a reliable entropy score.
MIN_STRING_LENGTH = 16

# Above this score a string looks random enough to be suspicious.
ENTROPY_THRESHOLD = 4.0

# Quoted values assigned to a variable or `key:` and at least 8 chars long.
CANDIDATE_STRING_PATTERN = re.compile(
    r"""
    [a-zA-Z_][a-zA-Z0-9_]*      # variable/key name
    \s*[:=]\s*                  # assignment separator
    ['"]([^'"]{8,})['"]         # the quoted value
    """,
    re.VERBOSE,
)


def shannon_entropy(data: str) -> float:
    """Shannon entropy of a string; 0.0 for empty input."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def find_entropy_candidates(line: str):
    """Return entropy info for every quoted assignment found on a line."""
    results = []

    for match in CANDIDATE_STRING_PATTERN.finditer(line):
        value = match.group(1)

        if len(value) < MIN_STRING_LENGTH:
            continue

        score = shannon_entropy(value)

        results.append({
            "value": value,
            "entropy": round(score, 2),
            "suspicious": score >= ENTROPY_THRESHOLD,
        })

    return results