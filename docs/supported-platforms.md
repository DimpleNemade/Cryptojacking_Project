# Supported Platform Policy

## Locally validated for 0.1.0a2

- Windows 11 10.0.26200, x86-64.
- CPython 3.12.4.
- `yara-python` 4.5.4.

## CI contract

The repository configures Windows and Ubuntu runners for CPython 3.10, 3.11, and
3.12. A platform/version combination is release-validated only when the exact
release commit has a green required CI job. Workflow configuration alone is not a
test result.

## Not validated

- macOS and ARM64.
- Python below 3.10 or 3.13 and later; package metadata rejects these versions.
- Other YARA implementations or versions outside `>=4.3,<5`.
- Operating-system memory-analysis behavior; this tool scans supplied files.

Alpha support is best-effort and has no SLA.
