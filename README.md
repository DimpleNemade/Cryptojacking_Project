# Cryptojacking Forensic Triage

> **Alpha software.** This is a research/education triage tool, not a finished or
> supported product. Findings are analyst leads and require human validation. It is
> not court-ready, not enterprise-ready, and does not prove compromise.

`cj-triage` is an offline, evidence-aware command-line tool that scans a supplied
artifact for cryptojacking indicators. It uses an in-process YARA engine, a bounded
string extractor, a versioned rule pack, and a privacy-safe reporter. It records
reproducibility metadata, fails closed when analysis is incomplete, and produces
explainable findings for analyst review.

## What it does

- Resolves and hashes a supplied artifact before analysis (SHA-256).
- Scans in-process with a curated YARA rule pack (`yara-python`).
- Extracts bounded printable/UTF-16LE strings (no unbounded reads).
- Builds structured findings with evidence strength, analytic confidence, and
  deterministic correlation.
- Produces schema-validated manifest, summary, and findings reports.
- Re-hashes after analysis; detects integrity failure as a distinct terminal state.
- Verifies its own reports (schema + output-hash tamper detection).

## What it does not do

- Acquire evidence, parse OS memory, or attribute strings to processes.
- Provide chain of custody, write protection, or legal admissibility.
- Run as an EDR/SIEM/runtime agent or monitor live behavior.
- Prove a host was compromised.
- Validate wallet checksums, ownership, or network activity.

## Supported platforms and Python

| OS | Python | Status |
|---|---|---|
| Windows 10+ | 3.10–3.12 | Supported (CI) |
| Ubuntu 22.04+ | 3.10–3.12 | Supported (CI) |
| macOS / ARM64 | 3.10–3.12 | Not validated |

Engine: `yara-python` (in-process). See `docs/supported-platforms.md`.

## Safe installation

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows  (or: source .venv/bin/activate)
pip install -e ".[dev]"       # editable dev install
# or from a built wheel:
pip install cryptojacking_forensics-0.1.0a1-py3-none-any.whl
# or with pipx:
pipx install cryptojacking_forensics-0.1.0a1-py3-none-any.whl
```

The only runtime dependency is `yara-python`. No external `yara` or GNU `strings`
binary is required.

## `cj-triage --help`

```
cj-triage --help
cj-triage scan artifact --help
```

## Safe synthetic-fixture quickstart

```bash
cj-triage scan artifact tests/fixtures/synthetic_miner_indicators.txt --case-id QUICKSTART
```

The fixture is inert text. It is not malware and contains only known indicator
strings for testing.

## Core CLI examples

```bash
# Scan an artifact
cj-triage scan artifact PATH --case-id CASE001

# Scan with explicit output dir and bundled rules
cj-triage scan artifact PATH --case-id CASE001 --output ./out --rules ./cryptojacking_forensics/rules

# Machine-readable JSON to stdout
cj-triage scan artifact PATH --case-id CASE001 --format json

# Environment and rule-pack check
cj-triage doctor
cj-triage rules check

# Verify a previously produced report
cj-triage verify-report ./out/CASE001/<run>/summary.json

# Version
cj-triage version
```

## Exit-code table

| Code | Meaning |
|---|---|
| `0` | Completed successfully, no findings. |
| `10` | Completed successfully, findings present. |
| `20` | Incomplete or partial analysis. |
| `30` | Evidence integrity failure. |
| `64` | Command usage or configuration error. |
| `70` | Internal or unrecoverable execution failure. |

A failed, partial, or integrity-failure analysis never exits `0` and is never
labelled "clean."

## Output artifact table

| File | Purpose |
|---|---|
| `manifest.json` | Execution record: input identity/hashes, stages, engine/rule versions, limits, controls, output hashes. |
| `findings.json` | Structured YARA and string findings with correlation. |
| `summary.json` | Machine-readable status, evidence strength, counts, limitations. |
| `summary.txt` | Human-readable summary. |
| `strings.txt` | Extracted strings (only with `--raw`). |

## Finding interpretation

Each finding has an `evidence_strength` (`STRONG`/`MEDIUM`/`WEAK`/`NONE`) and an
analytic `confidence`. Findings are correlated into independent indicator groups;
the `unvalidated_triage_score` is a bounded count of those groups, **not** a
probability or risk score. Review `findings.json` for context before drawing any
conclusion.

## Evidence-integrity boundaries

- Read-only open does not prove write protection.
- Pre/post hashes check that bytes were unchanged *during this tool's analysis*;
  they do not establish acquisition provenance or chain of custody.
- Integrity failure (`30`) is a distinct, terminal state.

## Privacy and redaction behavior

By default the tool omits raw strings and absolute paths. Report outputs keep only
display (basename) paths. Use `--raw` only when the evidence context is controlled
and you accept the disclosure risk. Redaction before external sharing remains the
analyst's responsibility.

## Rule pack

Bundled rules live in `cryptojacking_forensics/rules/` and carry metadata (rule ID,
version, author, purpose, references, MITRE ATT&CK where justified, confidence
rationale, known false positives, last-reviewed). See `rules/rule_pack.json`.

## Validation status

61 tests pass locally (Windows / Python 3.11.15); Ubuntu + Windows CI matrix runs
on 3.10–3.12. See `docs/VALIDATION.md` for the full record and known false
positive/negative risks. Synthetic tests do not establish real-world detection
performance.

## Development commands

```bash
python -m pytest -ra                       # run tests
python -m pytest --cov=cryptojacking_forensics   # coverage
python -m cryptojacking_forensics doctor   # environment check
python -m cryptojacking_forensics rules check    # rule compilation
python tasks.py help                       # task runner (setup/test/lint/build/validate)
```

## Security reporting

Use GitHub **private vulnerability reporting** (Security tab). Do not open public
issues for security defects, and never attach malware, miner binaries, credentials,
or live evidence. See `SECURITY.md`.

## License

Apache-2.0. Third-party components (notably `yara-python`) retain their own
licenses; see `LICENSE` for notices. The project does not claim ownership of
third-party samples, rules, or code.

## Links

- Roadmap: [`docs/project-roadmap.html`](docs/project-roadmap.html)
- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Validation: [`docs/VALIDATION.md`](docs/VALIDATION.md)
- Limitations: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)
- Threat model: [`docs/threat-model.md`](docs/threat-model.md)
- Safe-sample policy: [`docs/safe-sample-policy.md`](docs/safe-sample-policy.md)
