"""Simple regex patterns for common secret formats."""

import re

REGEX_DETECTORS = [
    {
        "name": "Generic API Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]"""
        ),
    },
    {
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]"""
        ),
    },
    {
        "name": "Generic Access Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(access[_-]?token|auth[_-]?token|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{16,})['"]"""
        ),
    },
    {
        "name": "GitHub Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(gh[pousr]_[A-Za-z0-9]{20,})"""
        ),
    },
    {
        "name": "AWS Access Key ID",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""\b(AKIA[0-9A-Z]{16})\b"""
        ),
    },
    {
        "name": "AWS Secret Access Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)aws_secret_access_key\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]"""
        ),
    },
    {
        "name": "JWT (JSON Web Token)",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"""(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"""
        ),
    },
    {
        "name": "Generic Secret",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"""(?i)(secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{8,})['"]"""
        ),
    },
]


def scan_line_with_regex(line: str):
    """Run every detector against one line and return matching secrets."""
    findings = []

    for detector in REGEX_DETECTORS:
        match = detector["pattern"].search(line)
        if match:
            # Use the last capture group if present (the secret value
            # itself), otherwise the whole match.
            if match.groups():
                matched_value = match.groups()[-1]
            else:
                matched_value = match.group(0)

            findings.append({
                "name": detector["name"],
                "severity": detector["severity"],
                "matched_value": matched_value,
            })

    return findings