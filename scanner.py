#!/usr/bin/env python3
"""
scanner.py

Secrets-in-Code Scanner
------------------------
A basic CLI tool to scan a local project directory for hardcoded
secrets BEFORE running `git add`.

Usage:
    python scanner.py .
    python scanner.py ./my-project

Exit codes:
    0 -> no potential secrets found (PASSED)
    1 -> potential secrets found (FAILED)

This tool does NOT modify any files and does NOT run any git commands.
It only reads files and prints a report.
"""

import os
import sys

from detectors import scan_line_with_regex
from entropy import find_entropy_candidates
from reporter import print_header, print_finding, print_summary, redact


# ---------------------------------------------------------------------
# Configuration (easy to edit)
# ---------------------------------------------------------------------

# File extensions we consider "source/config" files worth scanning.
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".java", ".cpp", ".c", ".h", ".php", ".go", ".rs",
    ".json", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf",
    ".env", ".txt",
}

# Directories to skip entirely.
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
}


# ---------------------------------------------------------------------
# Step 1: Recursive file walker
# ---------------------------------------------------------------------

def is_binary_file(file_path: str, blocksize: int = 1024) -> bool:
    """
    Heuristic check to skip binary files: if a chunk of the file
    contains a null byte, treat it as binary.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(blocksize)
        return b"\x00" in chunk
    except OSError:
        # If we can't read it, treat it as unreadable/binary-ish
        return True


def find_scannable_files(root_dir: str):
    """
    Recursively walk `root_dir`, yielding file paths that:
        - are not inside an ignored directory
        - have a scannable extension
        - are not binary files
    """
    for current_dir, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames in-place to prevent os.walk from descending
        # into ignored directories (e.g. .git, node_modules, venv).
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCANNABLE_EXTENSIONS:
                continue

            file_path = os.path.join(current_dir, filename)

            if is_binary_file(file_path):
                continue

            yield file_path


# ---------------------------------------------------------------------
# Steps 2-4: Combined regex + entropy scanning
# ---------------------------------------------------------------------

def scan_file(file_path: str):
    """
    Scan a single file line-by-line for secrets using both
    regex detection and Shannon entropy detection.

    Returns a list of finding dicts ready for the reporter.
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[WARN] Could not read {file_path}: {e}", file=sys.stderr)
        return findings

    for line_number, line in enumerate(lines, start=1):
        # --- Regex detection ---
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

        # --- Entropy detection ---
        # To avoid double-reporting the same value that regex already
        # caught, we skip entropy candidates that overlap with a
        # regex-matched value on the same line.
        regex_matched_values = {hit["matched_value"] for hit in regex_hits}

        entropy_candidates = find_entropy_candidates(line)
        for candidate in entropy_candidates:
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


# ---------------------------------------------------------------------
# Step 6: Orchestration, report, exit codes
# ---------------------------------------------------------------------

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
        file_findings = scan_file(file_path)
        all_findings.extend(file_findings)

    for finding in all_findings:
        print_finding(finding)

    print_summary(files_scanned, len(all_findings))

    # Exit code contract:
    # 0 = PASSED (no secrets found)
    # 1 = FAILED (potential secrets found)
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
