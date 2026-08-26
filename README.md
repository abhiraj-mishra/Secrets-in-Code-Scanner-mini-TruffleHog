# Secrets-in-Code Scanner

A basic, educational secrets scanner inspired by TruffleHog/GitLeaks —
built to run **manually before `git add`**, so you catch hardcoded
secrets before they ever get staged or committed.

## Workflow

```
Write/modify code
       ↓
python scanner.py .
       ↓
Secret found?
   YES       NO
    ↓         ↓
Fix secret   git add .
              ↓
           git commit
```

The scanner **never modifies files** and **never runs git commands**.
It only reads files and prints a report.

## Usage

```bash
python scanner.py .
python scanner.py ./my-project
```

## How it works

Two detection methods, combined:

1. **Regex detection** (`detectors.py`) — matches common secret shapes:
   API keys, passwords, access tokens, GitHub tokens (`ghp_...`),
   AWS access keys (`AKIA...`), AWS secret keys, JWTs, generic secrets.

2. **Shannon entropy** (`entropy.py`) — flags quoted values assigned to
   a variable that "look random" (high entropy), which regex alone
   would miss. Entropy is a *hint*, not proof — it's combined with
   context (must look like `key = "value"`) to reduce false positives.

Findings from both methods are merged, secrets are **redacted** before
printing (`reporter.py`), and a final summary is shown.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | No potential secrets found (PASSED) |
| 1    | Potential secrets found (FAILED) |

This makes it easy to wire into a CI step or pre-commit hook later —
**but that wiring is intentionally not implemented in this version.**

## Project structure

```
secrets-scanner/
├── scanner.py       # CLI entry point, file walking, orchestration
├── detectors.py      # regex-based detectors
├── entropy.py        # Shannon entropy calculator
├── reporter.py       # redaction + terminal report formatting
├── test_project/
│   ├── example.py    # FAKE credentials, for testing only
│   └── config.txt    # FAKE credentials, for testing only
└── README.md
```

## Testing it yourself

```bash
python scanner.py ./test_project
```

Expected: several findings, exit code `1`.

```bash
mkdir clean_test && echo 'x = "hello"' > clean_test/ok.py
python scanner.py ./clean_test
```

Expected: 0 findings, exit code `0`.

## Configuration

Edit these near the top of `scanner.py`:

- `SCANNABLE_EXTENSIONS` — file extensions to scan
- `IGNORED_DIRS` — directories to skip (`.git`, `node_modules`, etc.)

Edit thresholds in `entropy.py`:

- `MIN_STRING_LENGTH` — minimum length before entropy is checked
- `ENTROPY_THRESHOLD` — entropy score above which a string is "suspicious"

## Explicitly NOT included (by design)

Web dashboard, database, machine learning, cloud integration, GitHub
API, git history scanning, automatic `git add`/`git commit`, CI/CD,
Docker, authentication, or an automatic pre-commit hook. These are
noted as possible future improvements, not part of this basic version.

## ⚠️ Important

All credentials in `test_project/` are **fake, for testing purposes
only**. Never commit real secrets to a repository, even a private one.
