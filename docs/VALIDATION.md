# Validation Record

## Purpose

This validation checks whether the `cj-triage` CLI behaves as documented for
controlled synthetic inputs. It covers automated tests, real in-process YARA
(`yara-python`) and bounded string extraction, report generation, finding
correlation, schema validation, report verification, and pre/post evidence hashing.
This is triage validation, not legal-admissibility validation.

## Environment matrix

| Property | Value |
|---|---|
| Validation date | 2026-08-09 |
| OS | Windows 10 (validation host) + Ubuntu 22.04 (CI, see `.github/workflows/ci.yml`) |
| Python | CPython 3.11.15 (local); 3.10/3.11/3.12 (CI matrix) |
| pytest | 8.4.x |
| Engine | `yara-python` 4.5.4 |
| Wheel | built with `python -m build --wheel`; installed clean outside source tree |

## Commands

```bash
python -m pytest -ra
python -m pytest --cov=cryptojacking_forensics --cov-report=term-missing
python -m cryptojacking_forensics doctor
python -m cryptojacking_forensics rules check
python -m cryptojacking_forensics scan artifact tests/fixtures/synthetic_miner_indicators.txt --case-id VALIDATION_SYNTHETIC
python -m cryptojacking_forensics verify-report <run>/summary.json
```

## Fixtures

- `tests/fixtures/clean_sample.txt`: inert text with no intended miner indicator.
- `tests/fixtures/synthetic_miner_indicators.txt`: inert text containing known
  XMRig and Stratum/configuration strings. It is not malware.

## Actual results (this run)

- Automated suite: **61 tests passed** (Windows 10 / Python 3.11.15).
- Clean fixture: `SUCCESS`, hash `PASS`, 0 findings, exit `0`.
- Synthetic indicator fixture: `SUCCESS`, hash `PASS`, 8 findings grouped into 5
  independent indicator groups, evidence strength `MEDIUM`, exit `10`.
- Rule pack compiles; `rules check` reports OK.
- Wheel builds and installs in a clean venv outside the source tree; `cj-triage
  --version` and a synthetic scan (exit 10) succeed from that environment.
- Schema validation of manifest/summary/findings passes; `verify-report` detects
  tampered (schema-invalid) reports (exit 70).
- Engine timeout param handled without crash; match-cap truncation reported.
- Exit-code contract verified for 0/10/20/30/64/70 across tests.

### Coverage (local, this run; not the 85% target automatically)

Overall ~66%. Core paths are higher: engine 90%, evidence 86%, findings 85%,
hashing/strings 100%. The CLI command surface is exercised via subprocess tests;
in-process statement coverage of `cli.py` is lower because subprocess runs count
against the spawned interpreter. No code path is left untested by design — see the
engineering target note below.

> Engineering target: at least 85% overall, with higher coverage for evidence,
> status, exit-code, and report-validation paths. The target is a goal, not a
> claim; the measured value above is the actual result for this run.

## Analysis status behavior

- `SUCCESS`: all stages succeeded, rules present, pre/post hashes matched.
- `PARTIAL`: at least one stage succeeded and at least one failed, or rules absent.
- `FAILED`: no analysis stage succeeded while evidence hashing still passed.
- `INTEGRITY_FAILURE`: pre/post evidence hash verification did not pass.
- `UNDETERMINED` severity is used when status is not `SUCCESS`; a non-SUCCESS report
  is **never** labelled "clean."

## Known false-positive risks

- Miner names, Stratum strings, common mining ports, pool-related words, and
  wallet-shaped strings can occur in benign files, documentation, logs, or security
  research material.
- Wallet candidates are format-based only; not checksum-validated.
- Multiple rules may match one underlying string; correlation reduces count
  inflation but does not prove a common cause.

## Known false-negative risks

- Obfuscated, encrypted, compressed, encoded, fragmented, or novel indicators may
  not be visible to the rule pack.
- The rule set is limited and cannot cover every miner, pool, protocol variant, or
  wallet format.
- Extracted strings are not associated with processes or OS memory structures.

## Not performed / not validated

- Real malware or live miner binaries (excluded by safe-sample policy).
- Large real memory dumps.
- macOS/ARM64 operation (unverified).
- Independent external validation (a separate, non-developer review is recommended
  before any claimed operational use).

Synthetic validation does **not** establish real-world detection performance or
legal admissibility.
