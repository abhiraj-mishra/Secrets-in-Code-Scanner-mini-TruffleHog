"""
entropy.py

Shannon entropy calculation for detecting random-looking strings
(which are often API keys, tokens, or other secrets).

Formula:
    H(X) = -Σ p(x) * log2(p(x))

Where p(x) is the probability of character x appearing in the string.

A HIGH entropy score means the string looks "random" (lots of different
characters, no repeating patterns) -- which is typical of generated
secrets like API keys or tokens.

A LOW entropy score means the string is more predictable/repetitive,
like normal English words or simple variable names.

NOTE: Entropy alone is NOT proof of a secret. A random UUID, a hash,
or a long random-looking sentence can also have high entropy. This is
why entropy detection is combined with regex detection and some basic
heuristics (like "does this look like it's inside a quoted string
assigned to a variable?").
"""

import math
import re
from collections import Counter

# Minimum string length to even bother checking entropy on.
# Very short strings don't give reliable entropy scores.
MIN_STRING_LENGTH = 16

# Entropy score above this is considered "suspicious".
# Typical thresholds used by tools like TruffleHog/GitLeaks are
# somewhere around 3.5 - 4.5 depending on charset assumptions.
ENTROPY_THRESHOLD = 4.0

# Regex to find "candidate" strings worth checking for entropy:
# - quoted strings assigned to a variable (key = "....", key: "....")
# This avoids running entropy checks on every word in every file.
CANDIDATE_STRING_PATTERN = re.compile(
    r"""
    [a-zA-Z_][a-zA-Z0-9_]*      # variable/key name
    \s*[:=]\s*                  # assignment or key-value separator
    ['"]([^'"]{8,})['"]         # the quoted value (min 8 chars)
    """,
    re.VERBOSE,
)


def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    H(X) = -Σ p(x) * log2(p(x))

    Returns a float. Higher = more random-looking.
    Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def find_entropy_candidates(line: str):
    """
    Scan a single line of text for candidate strings (quoted values
    assigned to a variable) and compute their entropy.

    Returns a list of dicts:
        {
            "value": the raw candidate string,
            "entropy": float entropy score,
            "suspicious": bool (entropy above threshold and long enough)
        }
    """
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
