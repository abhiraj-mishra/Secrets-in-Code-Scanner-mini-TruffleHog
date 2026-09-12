"""Report formatting and secret redaction."""


def redact(value: str, show_chars: int = 4) -> str:
    """Keep the first few characters, mask the rest with asterisks."""
    if not value:
        return ""

    if len(value) <= show_chars:
        return value[0] + "*" * (len(value) - 1) if len(value) > 1 else "*"

    return value[:show_chars] + "*" * (len(value) - show_chars)


def print_header():
    print("=" * 40)
    print("     SECRETS-IN-CODE SCANNER")
    print("=" * 40)
    print()


def print_finding(finding: dict):
    """Print a single finding."""
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