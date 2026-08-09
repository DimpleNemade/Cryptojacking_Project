# Architecture

```text
cj-triage
  cli.py                 commands, status model, exit codes, privacy mode
  case.py                contained, unique run directories
  evidence.py            pre/post hash and file-identity observations
  engine.py              in-process YARA file scanning
  strings_extractor.py   bounded streaming ASCII/UTF-16LE extraction
  findings.py            deterministic findings, redaction, correlation
  reporting*.py          strict schemas, atomic writes, bundle verification
  rules/                  packaged rule pack and metadata
  schemas/                versioned public JSON contracts
```

## Scan flow

1. Validate the case ID and resolve the input.
2. Record file identity and SHA-256 using read-only opens.
3. Allocate a contained run directory so incomplete analyses can still report.
4. Compile packaged or operator-selected YARA rules.
5. Ask `yara-python` to scan the file directly with the remaining deadline.
6. Stream printable ASCII and UTF-16LE strings with bounded storage and the same
   stage deadline.
7. Re-stat and re-hash the input. Any byte or identity change is terminal.
8. Build deterministic findings, redact raw values unless explicitly requested,
   and validate all documents against packaged schemas.
9. Atomically write findings/summary, hash those immutable siblings, then write
   the manifest. The manifest does not hash itself.

The deadline bounds YARA and string-analysis stages. Pre/post integrity hashing is
allowed to finish even if the stage deadline is exhausted so the run can report an
integrity result.

## Security boundaries

- The tool never intentionally opens the source for writing, but this does not
  establish a hardware or OS write block.
- Pre/post agreement establishes only that the observed bytes and identity did not
  change during this run.
- Report filenames are fixed, JSON is escaped by the encoder, writes are atomic,
  and owner-only permissions are attempted where the platform supports them.
- Raw matched values, raw strings, absolute input paths, and absolute report paths
  are opt-in through `--raw`.
- Missing rules, timeouts, truncation, read failures, and integrity failures cannot
  produce a successful-clean exit.
