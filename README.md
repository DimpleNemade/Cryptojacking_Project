# Cryptojacking Artifact Triage

> **Alpha software.** `cj-triage` produces analyst leads from supplied files. It is
> not a memory-forensics engine, evidence-acquisition system, EDR, proof of
> compromise, or legally determinative forensic instrument.

`cj-triage` is an offline command-line tool for bounded cryptojacking-indicator
triage. It combines in-process YARA scanning with streaming ASCII/UTF-16LE string
extraction and emits versioned, integrity-verifiable JSON reports.

## What is delivered

- A standards-based Python package and `cj-triage` console command.
- File scanning through `yara-python`; no external `yara` or GNU `strings` binary.
- Streaming extraction with input, match, output, per-string, and time limits.
- Pre/post SHA-256 and file-identity observations; changes fail with exit `30`.
- Stable exit codes and fail-closed `PARTIAL`/`FAILED` states.
- Strict JSON Schemas for manifest, summary, and findings documents.
- Manifest verification of sibling artifact hashes.
- Safe report defaults: raw matched values and absolute paths require `--raw`.
- A versioned rule pack and inert synthetic tests only.

## What is not established

- Real-world detection accuracy, coverage, false-positive rate, or evasion resistance.
- Operating-system memory parsing or attribution to a running process.
- Acquisition provenance, write blocking, chain of custody, or admissibility.
- Production, enterprise, or court readiness.
- Product-market fit, customer adoption, or revenue.

## Platform status

| Environment | Status for `0.1.0a2` |
|---|---|
| Windows 11 x86-64 / CPython 3.12.4 | Locally validated |
| Windows / Ubuntu, CPython 3.10-3.12 | CI matrix configured; trust only a green run for this revision |
| macOS, ARM64, Python 3.13+ | Not validated |

## Install

Python 3.10-3.12 is required.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX:   source .venv/bin/activate
python -m pip install -e ".[dev]"
```

From a locally built wheel:

```bash
python -m build
python -m pip install dist/cryptojacking_forensics-0.1.0a2-py3-none-any.whl
```

No PyPI publication is claimed.

## Use

```bash
cj-triage --help
cj-triage doctor
cj-triage rules check
cj-triage scan artifact tests/fixtures/synthetic_miner_indicators.txt --case-id QUICKSTART
cj-triage verify-report Reports/QUICKSTART/<run>
```

The quickstart fixture is inert text, not malware. A matching scan exits `10`, so
shell automation must treat both `0` and `10` as completed analyses.

Useful scan options:

```bash
cj-triage scan artifact PATH --case-id CASE001 --output ./Reports
cj-triage scan artifact PATH --case-id CASE001 --format json --quiet
cj-triage scan artifact PATH --case-id CASE001 --timeout 60 --min-length 6
cj-triage scan artifact PATH --case-id CASE001 --raw  # explicit disclosure opt-in
```

## Exit codes

| Code | Contract |
|---|---|
| `0` | All stages completed; no configured indicators found. |
| `10` | All stages completed; findings present. |
| `20` | Analysis partial or failed; never interpret as clean. |
| `30` | Evidence identity/integrity failure. |
| `64` | Invalid command, option, path, or configuration. |
| `70` | Internal failure or schema-invalid report. |

## Reports

Each run creates a unique `OUTPUT/CASE_ID/RUN_ID/` directory:

| File | Purpose |
|---|---|
| `manifest.json` | Versions, rules and hashes, effective limits, stage states, evidence observations, and hashes of sibling outputs. |
| `summary.json` | Terminal status, counts, evidence strength, warnings, errors, and limitations. |
| `findings.json` | Versioned findings, offsets, indicator hashes, evidence strength, and correlation. |
| `strings.txt` | Raw extracted values; created only with `--raw`. |

`cj-triage verify-report RUN_DIRECTORY` or a `manifest.json` path validates the
manifest schema and sibling hashes. Passing an individual summary/findings file
validates only that file's schema.

The manifest never hashes itself: embedding a hash of the finalized manifest
inside that same manifest would be self-referential and unverifiable.

## Interpreting findings

Evidence strength is a transparent rule/indicator label, not a probability or
risk score. Repeated observations are grouped so the report does not present each
occurrence as an independent fact. Matched values are SHA-256 represented by
default; `--raw` is required to include them. Hashing is pseudonymization, not
anonymization: low-entropy/common values can be guessed and re-hashed.

## Development and validation

```bash
python -m ruff check cryptojacking_forensics tests tasks.py
python -m pytest --cov=cryptojacking_forensics --cov-fail-under=85
python -m pre_commit run --all-files
pip-audit -r requirements-audit.txt --strict
python -m build
```

The local 2026-08-10 validation passed 46 tests at 85.35% statement coverage on
Windows 11 / CPython 3.12.4, built wheel and sdist artifacts, installed the wheel
outside the source tree, ran the packaged CLI, and verified its report bundle.
This synthetic validation does not measure real-world detection performance.

## Safety and project records

- Never attach or commit live malware, miner binaries, credentials, or case evidence.
- Report vulnerabilities privately through GitHub's Security tab; see [SECURITY.md](SECURITY.md).
- Read the [validation record](docs/VALIDATION.md), [limitations](docs/LIMITATIONS.md),
  [architecture](docs/architecture.md), [safe-sample policy](docs/safe-sample-policy.md),
  and [evidence-based roadmap](docs/project-roadmap.html).

Apache-2.0. Third-party components retain their own licenses.
