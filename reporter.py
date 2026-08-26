"""
reporter.py

Handles:
    - Redacting secret values before printing (never show full secrets)
    - Formatting the terminal report shown to the user
"""

def redact(value: str, show_chars: int = 4) -> str:
    """
    Redact a secret value, keeping only the first `show_chars`
    characters visible, replacing the rest with asterisks.

    Example:
        redact("sk_test_123456789abcdef") -> "sk_t********************"
    """
    if not value:
        return ""

    if len(value) <= show_chars:
        # Very short values: redact almost everything anyway
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"

    visible = value[:show_chars]
    hidden = "*" * (len(value) - show_chars)
    return visible + hidden


def print_header():
    print("=" * 40)
    print("     SECRETS-IN-CODE SCANNER")
    print("=" * 40)
    print()


def print_finding(finding: dict):
    """
    Print a single finding in the required format.

    Expected keys in `finding`:
        severity, secret_type, file_path, line_number, method,
        redacted_value, entropy (optional)
    """
    print(f"[{finding['severity']}] {finding['secret_type']}")
    print(f"File   : {finding['file_path']}")
    print(f"Line   : {finding['line_number']}")
    print(f"Method : {finding['method']}")

    if finding.get("entropy") is not None:
        print(f"Entropy: {finding['entropy']}")

    print(f"Value  : {finding['redacted_value']}")
    print()


def print_summary(files_scanned: int, secrets_found: int):
    print("-" * 40)
    print(f"Files scanned       : {files_scanned}")
    print(f"Potential secrets   : {secrets_found}")
    status = "FAILED" if secrets_found > 0 else "PASSED"
    print(f"Status              : {status}")
    print("=" * 40)
