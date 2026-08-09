# Architecture Overview

## Components

```
cj-triage (console_script)
   -> cli.py            command parsing, exit codes, output discipline
      -> case.py        case/run directory management (unique, contained)
      -> evidence.py    read-only open, pre/post hashing, observed controls
      -> engine.py      in-process YARA (yara-python) compile + scan
      -> strings_extractor.py  bounded ASCII/UTF-16LE extraction
      -> findings.py    build findings, evidence strength, correlation
      -> manifest.py / reporting_ext.py  manifest + summary assembly
      -> reporting.py   schema validation, atomic writes, hashing
   rules/               bundled YARA rule pack (versioned, metadata-rich)
   schemas/             versioned JSON Schemas (manifest/summary/findings)
```

## Data flow
1. `scan artifact INPUT --case-id C` resolves and validates the case ID.
2. `evidence.inspect_before` opens read-only, records size/mtime, hashes (SHA-256).
3. Input bytes are scanned in-process by the compiled rule pack.
4. Strings are extracted with bounded caps (min length, max strings, max bytes).
5. Findings are built with evidence strength + confidence + correlation.
6. Report directory is created uniquely; outputs written atomically with 0o600.
7. `evidence.inspect_after` re-hashes; integrity failure is a distinct terminal state.
8. Manifest/summary/findings are schema-validated and hashed for tamper detection.

## Design constraints (from AGENTS.md)
- One package implementation, one documented command.
- Fail closed: incomplete analysis is never reported as clean.
- Privacy-safe defaults; raw output only on explicit opt-in.
- No overclaimed forensic/legal guarantees.

## Extension points
- New rules: add to `rules/` with the required metadata block; compile-checked in CI.
- New engines: implement the same `compile_rules`/`scan_bytes` interface (ADR-0001).
- New report formats: add a schema under `schemas/` and a writer in `reporting.py`.
