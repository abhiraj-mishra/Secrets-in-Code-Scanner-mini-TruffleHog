#!/usr/bin/env python3
"""CLI entry point for the secrets-in-code scanner.

Scans a directory for hardcoded secrets so they can be removed before
running `git add`. The tool only reads files; it never modifies them and
never runs git commands.

Usage:
    python scanner.py .
    python scanner.py ./my-project
"""

import os
import sys

from detectors import scan_line_with_regex
from entropy import find_entropy_candidates
from reporter import print_header, print_finding, print_summary, redact

# File types we care about.
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".java", ".cpp", ".c", ".h", ".php", ".go", ".rs",
    ".json", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf",
    ".env", ".txt",
}

# Directories that never contain source we want to scan.
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
}


def is_binary_file(file_path: str, blocksize: int = 1024) -> bool:
    """Heuristic: a null byte in the first chunk means the file is binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(blocksize)
        return b"\x00" in chunk
    except OSError:
        return True


def find_scannable_files(root_dir: str):
    """Yield readable, non-binary files under root_dir with a known extension."""
    for current_dir, dirnames, filenames in os.walk(root_dir):
        # Drop ignored dirs in place so os.walk never descends into them.
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCANNABLE_EXTENSIONS:
                continue

            file_path = os.path.join(current_dir, filename)
            if not is_binary_file(file_path):
                yield file_path


def scan_file(file_path: str):
    """Run regex and entropy detection over every line of a file."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[WARN] Could not read {file_path}: {e}", file=sys.stderr)
        return findings

    for line_number, line in enumerate(lines, start=1):
        regex_hits = scan_line_with_regex(line)
        for hit in regex_hits:
            findings.append({
                "severity": hit["severity"],
                "secret_type": hit["name"],
                "file_path": file_path,
                "line_number": line_number,
                "method": "Regex",
                "redacted_value": redact(hit["matched_value"]),
                "entropy": None,
            })

        # Skip entropy hits whose value regex already caught on this line,
        # so the same secret is reported only once.
        regex_matched_values = {hit["matched_value"] for hit in regex_hits}

        for candidate in find_entropy_candidates(line):
            if not candidate["suspicious"]:
                continue
            if candidate["value"] in regex_matched_values:
                continue

            findings.append({
                "severity": "MEDIUM",
                "secret_type": "High Entropy String",
                "file_path": file_path,
                "line_number": line_number,
                "method": "Entropy",
                "redacted_value": redact(candidate["value"]),
                "entropy": candidate["entropy"],
            })

    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <directory>")
        sys.exit(1)

    target_dir = sys.argv[1]

    if not os.path.isdir(target_dir):
        print(f"Error: '{target_dir}' is not a valid directory.")
        sys.exit(1)

    print_header()

    all_findings = []
    files_scanned = 0

    for file_path in find_scannable_files(target_dir):
        files_scanned += 1
        all_findings.extend(scan_file(file_path))

    for finding in all_findings:
        print_finding(finding)

    print_summary(files_scanned, len(all_findings))

    # 0 = PASSED (no secrets), 1 = FAILED (potential secrets found).
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()