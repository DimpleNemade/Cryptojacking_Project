# Validation Record

## Purpose

This validation checks whether the cryptojacking forensic triage CLI behaves as
documented for controlled synthetic inputs. It covers automated tests, real local
YARA and GNU strings execution, report generation, finding correlation, and
pre/post evidence hashing. This is triage validation, not legal admissibility
validation.

## Validation record

- Validation date: 2026-07-01.
- Validation location: local project workspace on the system described below.
- Operating system: Ubuntu 24.04.3 LTS, Linux 6.14.0-37-generic, x86_64.
- Python: 3.12.3 from the project virtual environment.
- pytest: 8.4.2.
- YARA: 4.5.0.
- GNU strings: GNU Binutils for Ubuntu 2.42.
- Automated test command: `./venv/bin/python -m pytest -ra`.

## Fixtures

- `tests/fixtures/clean_sample.txt`: inert text with no intended miner indicator.
- `tests/fixtures/synthetic_miner_indicators.txt`: inert text containing known
  Xmrig and Stratum/configuration strings. It is not malware.

## Expected results

| Check | Expected result |
|---|---|
| Automated tests | All collected tests pass. |
| Clean fixture | `SUCCESS`, hash `PASS`, zero findings, severity `NONE`. |
| Synthetic indicator fixture | `SUCCESS`, hash `PASS`, expected YARA/string findings, severity `HIGH`. |
| Correlation | Repeated Xmrig and Stratum observations are marked as corroborating, not independent. |
| Hash verification | Unchanged input passes; a test mutation produces `INTEGRITY_FAILURE`. |
| Failed analysis commands | No clean result; status is `FAILED` or `PARTIAL` as applicable. |

## Actual results

- Baseline before this improvement pass: 23 tests passed.
- Final automated suite: 30 tests passed.
- Clean fixture: `SUCCESS`, hash verification `PASS`, 0 findings, 0 independent
  indicator groups, severity `NONE`.
- Synthetic indicator fixture: `SUCCESS`, hash verification `PASS`, 6 findings,
  2 independent indicator groups, severity `HIGH`.
- The synthetic findings were grouped into Xmrig and Stratum indicator groups;
  corroborating YARA and strings records were marked non-independent.
- Both fixtures produced `manifest.json`, `findings.json`, `summary.json`,
  `summary.txt`, `yara.txt`, and `strings.txt`.
- The broad wallet YARA expressions were removed. Wallet-format candidates are
  extracted from GNU strings output in Python and labelled low-confidence. The
  real fixture runs did not emit the previous wallet-regex performance warning.

## Hash verification behavior

The CLI records SHA-256 before and after analysis. Equal values produce `PASS`.
The automated mutation test changes the evidence during analysis and verifies
that the result becomes `INTEGRITY_FAILURE`, with severity `UNDETERMINED`.
This check does not validate evidence acquisition or provenance.

## Analysis status behavior

- `SUCCESS`: all configured YARA scans and strings extraction succeeded, rules
  were present, and the pre/post hashes matched.
- `PARTIAL`: at least one analysis component succeeded and at least one failed,
  or the configured YARA rules were absent.
- `FAILED`: no analysis component succeeded while evidence hashing still passed.
- `INTEGRITY_FAILURE`: pre/post evidence hash verification did not pass.

Tool-version lookup failures are recorded as warnings and do not alone change
the analysis status.

## Known false-positive risks

- Miner names, Stratum strings, common mining ports, pool-related words, and
  wallet-shaped strings can occur in benign files, documentation, logs, or
  security research material.
- Wallet candidates are based on character and length format only. They are not
  checksum-validated.
- Multiple rules may match one underlying string. Correlation metadata reduces
  count inflation but does not prove a common cause.

## Known false-negative risks

- Obfuscated, encrypted, compressed, encoded, fragmented, or novel indicators
  may not be visible to YARA or GNU strings.
- The rule set is limited and cannot cover every miner, pool, protocol variant,
  or wallet format.
- Extracted strings are not associated with processes or operating-system memory
  structures.

## Detection limitations

This is indicator scanning, not full memory forensics. Severity and confidence
labels are triage labels that require analyst review. The
`unvalidated_triage_score` is a capped count of independent correlated groups,
not a calibrated probability. See [Limitations](LIMITATIONS.md).

## Not validated

The following were not validated in this pass:

- real malware;
- large real memory dumps;
- cross-platform operation;
- permission failures;
- missing external tools in real runtime;
- timeout behavior outside mocked tests; and
- concurrent evidence modification outside the controlled automated mutation
  test.

Real-world detection performance and legal admissibility cannot be inferred from
these synthetic validation results.
