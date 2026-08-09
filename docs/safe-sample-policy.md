# Safe Sample Handling Policy

This project follows a strict safe-sample policy.

## Prohibited in the source distribution
- Live miner binaries (e.g. XMRig), malware, or dual-use executables.
- Memory images, evidence dumps, or case data.
- Archives bundling the above.
- Large binaries that bloat the repository.

## What is allowed
- Inert synthetic text fixtures under `tests/fixtures/` (no executable content).
- Documentation-derived string snippets needed for rule design.
- Bundled YARA rules under `cryptojacking_forensics/rules/` (text only).

## Historical cleanup
On 2026-08-09 the tracked repository removed:
- one Windows-invalid repository-root entry, and
- previously tracked executable, archive, checksum, and configuration artifacts
  that are prohibited by this policy.

These remain in Git history. A history rewrite was **not** performed because it is
destructive and requires separate explicit owner approval. The current working tree
may still contain locally quarantined, ignored material; the tracked tree and future
commits must not distribute it.

## Contribution rule
Never commit samples listed as prohibited. Real-world corpora belong in an
access-controlled, separately-governed location with documented provenance and
retention — not in this repository.
