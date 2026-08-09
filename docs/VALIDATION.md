# Validation Record: 0.1.0a2

## Scope

This record covers controlled synthetic inputs and the local distribution path. It
does not establish real-world cryptojacking detection performance, forensic
admissibility, or support for environments not listed as actually tested.

## Environment

| Property | Observed value |
|---|---|
| Date | 2026-08-10 |
| Host | Windows 11 10.0.26200, x86-64 |
| Python | CPython 3.12.4 |
| pytest | 8.4.2 |
| YARA engine | `yara-python` 4.5.4 |
| Package | `cryptojacking-forensics` 0.1.0a2 |

Ubuntu, Windows 10, and Python 3.10/3.11 were not locally executed in this record.
The GitHub workflow defines a Windows/Ubuntu and Python 3.10-3.12 matrix; that is a
configuration statement, not evidence of a green run for an unpublished revision.

## Commands reproduced

```bash
python -m ruff check cryptojacking_forensics tests tasks.py
python -m ruff format --check cryptojacking_forensics tests tasks.py
python -m mypy cryptojacking_forensics tests tasks.py
python -m pytest -ra
python -m pytest --cov=cryptojacking_forensics --cov-report=xml --cov-fail-under=85
python -m pytest tests/test_schema.py -ra
python -m cryptojacking_forensics doctor
python -m cryptojacking_forensics rules check
python -m pre_commit run --all-files --show-diff-on-failure
pip-audit -r requirements-audit.txt --strict
python -m build
cyclonedx-py environment <clean-python> --output-format JSON --output-file sbom.cdx.json --output-reproducible --validate --pyproject pyproject.toml --mc-type application
```

A second clean virtual environment installed only the built wheel and runtime
dependencies. From outside the source directory it ran:

```bash
cj-triage --version
cj-triage doctor
cj-triage rules check
cj-triage scan artifact synthetic_miner_indicators.txt --case-id WHEEL
cj-triage verify-report <generated-manifest>
```

## Observed results

- Ruff lint and format checks: passed.
- mypy: passed for 21 source/test/task files.
- Pre-commit hooks: passed, including YAML, size, conflict, secret, lint,
  formatting, typing, and rule-compilation checks.
- Runtime dependency audit: passed; no known vulnerabilities were reported for
  the direct runtime requirements or their resolved transitive dependencies.
- Tests: **46 passed**.
- Statement coverage: **85.35% overall**; engine 92%, evidence 92%, findings 88%,
  streaming string extraction 94%.
- Clean fixture: `SUCCESS`, no findings, integrity `PASS`, exit `0`.
- Synthetic fixture: `SUCCESS`, eight findings in five independent groups,
  evidence strength `MEDIUM`, integrity `PASS`, exit `10`.
- Missing rule pack: `PARTIAL`, exit `20`; it is not reported as clean.
- Oversized input: a failed report bundle is written, exit `20`.
- Schema-invalid report: exit `70`.
- Schema-valid sibling tampering: manifest verification detects the hash mismatch,
  exit `30`.
- Wheel and source distribution built successfully; the source distribution
  contains docs and inert fixtures and excludes the quarantined/excluded trees.
- Clean wheel install, packaged `doctor`, packaged rule compilation, packaged
  synthetic scan, and bundle verification succeeded.
- The package-content audit found zero entries from quarantined samples, the
  excluded repository copy, reports, virtual environments, or cache directories.
- CycloneDX generation and validation succeeded with specification 1.6, the
  `cryptojacking-forensics` 0.1.0a2 root component, and eight dependency components.

## What the tests prove

They provide repeatable evidence for the documented CLI states, limits, schema
contract, deterministic ordering/correlation, privacy defaults, artifact-hash
verification, and operation of the actual bundled YARA engine on inert fixtures.

## What the tests do not prove

- Detection precision, recall, false-positive rate, or coverage on real incidents.
- Resistance to obfuscation, compression, encryption, fragmentation, or new miners.
- Process execution, wallet ownership/activity, or host compromise.
- Evidence acquisition provenance, write blocking, chain of custody, or admissibility.
- Independent competent-person validation as recommended for examination tools.
- macOS, ARM64, Python 3.13+, or any unexecuted CI environment.

## Known test limitations

The corpus contains two inert text files. It has no versioned real-world labels,
benign hard negatives, evasive variants, held-out set, denominators, or confidence
intervals. Therefore no detection-performance percentage is reported.
