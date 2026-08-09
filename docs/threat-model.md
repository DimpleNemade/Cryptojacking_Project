# Threat Model

## What this tool is
An offline, evidence-aware cryptojacking indicator-triage CLI. It scans supplied
artifacts with an in-process YARA engine, extracts bounded strings, builds structured
findings, and produces reproducible reports. It does **not** execute samples, monitor
runtime behavior, or acquire evidence.

## Assets
- Supplied evidence/artifact files (potentially sensitive; may contain paths, wallet
  strings, or private data).
- Generated reports (findings, manifests, summaries) which may include evidence-derived
  content.
- The tool's own integrity (rules, schemas, code).

## Trust boundaries
- Input: untrusted artifact bytes. Treated as attacker-controlled data; never executed.
- Output: reports may leave the analyst machine. Privacy-safe defaults (no raw strings,
  no absolute paths) protect the source layout and sensitive strings unless opted in.
- Engine: yara-python runs in-process; rules are curated and compiled locally. Untrusted
  YARA modules are not loaded.

## Threats considered
- **Information disclosure**: absolute paths, wallet-shaped strings, raw strings in
  reports. Mitigation: privacy-safe defaults, `--raw` explicit opt-in, documented
  redaction responsibility.
- **Evidence tampering by the tool**: mitigated by read-only open, pre/post hashing,
  fail-closed on hash mismatch.
- **Malicious rule or sample execution**: rules are curated; samples are never executed.
- **Supply-chain compromise**: pinned dependencies, SBOM, CodeQL, dependency review,
  signed/attested releases (where supported).

## Explicitly out of scope
- Hardware write-blocking, chain of custody, acquisition provenance, legal admissibility.
  These are operational/legal processes, not software guarantees.

## Residual risk
Synthetic tests do not establish real-world detection performance. Independent
validation (separate from the developer) is recommended before any claimed use.
