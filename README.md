# Cryptojacking Forensic Triage

A Python-based cryptojacking forensic triage CLI that performs YARA scanning,
string extraction, pre/post SHA-256 evidence verification, structured finding
generation, run manifest creation, and repeatable case-based reporting.

This project scans a supplied file for indicators that may warrant analyst
review. It does not acquire evidence, parse operating-system memory structures,
attribute strings to processes, or prove that a host was compromised.

> Findings are triage leads. They require analyst validation and must not be
> treated as final forensic conclusions.

## What the tool does

- Resolves and hashes the supplied evidence file before analysis.
- Runs each local YARA rule file and GNU `strings` without a shell.
- Converts rule matches and selected extracted-string indicators into structured
  findings.
- Groups corroborating findings so repeated detection of the same underlying
  indicator is not presented as multiple independent indicators.
- Hashes the evidence again after analysis and reports whether it changed.
- Records command results, tool versions, rule hashes, warnings, errors, and
  output hashes in a run manifest.
- Creates a unique report directory for every invocation.

Wallet-format matching is performed over extracted strings in Python rather than
through broad YARA regular expressions. Each match is labelled
`WALLET_CANDIDATE` with `LOW` confidence. No checksum, ownership, activity, or
network validation is performed.

## What the tool does not do

- Evidence acquisition or chain-of-custody management.
- Process-aware or operating-system-aware memory parsing.
- Attribution of extracted strings to a running process.
- External IOC enrichment, reputation checks, or network requests.
- Validated compromise probability or automatic confirmation of compromise.
- Dedicated IOC export; candidate indicators remain in `findings.json`.

See [Limitations](docs/LIMITATIONS.md) for the complete scope statement and
[Validation](docs/VALIDATION.md) for the tested environment and observed results.

## Requirements and setup

- Python 3.10 or newer. The runtime package uses only the Python standard library.
- YARA command-line tool (`yara`).
- GNU binutils `strings`.
- pytest for development and testing, declared in `requirements-dev.txt`.

On Debian or Ubuntu, YARA and GNU strings are commonly supplied by the `yara`
and `binutils` packages. Installation and tool versions should be checked in the
analyst's controlled environment.

Create an isolated Python environment and install the development dependency:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -ra
```

There is no `requirements.txt` because the Python runtime has no third-party
package dependencies.

## Run

Run commands from the repository root. Case IDs must be 1-64 characters, start
with a letter or digit, and otherwise contain only letters, digits, periods,
underscores, or hyphens.

Clean synthetic fixture:

```bash
python -m cryptojacking_forensics \
  --memory tests/fixtures/clean_sample.txt \
  --case-id VALIDATION_CLEAN
```

Synthetic indicator-positive fixture:

```bash
python -m cryptojacking_forensics \
  --memory tests/fixtures/synthetic_miner_indicators.txt \
  --case-id VALIDATION_SYNTHETIC
```

The fixture is inert text and is not malware. It tests known rule and string
indicators only.

Equivalent compatibility entry points are:

```bash
python Tools/full_pipeline.py --memory FILE --case-id CASE001
./Scripts/run_pipeline.sh FILE CASE001
```

Each run writes to:

```text
Reports/<case_id>/<UTC timestamp>-<random suffix>/
```

## Output structure

- `manifest.json`: execution record containing input metadata, pre/post hashes,
  analysis status, executed commands, return codes, timings, tool versions, YARA
  rule hashes, warnings/errors, and hashes of the other output artifacts. It does
  not self-hash. Absolute paths are retained for traceability alongside safer
  display paths; see the privacy note below.
- `findings.json`: structured YARA and extracted-string findings. Correlation
  fields identify corroborating records and whether a record represents an
  independent indicator. An empty list is meaningful only when
  `analysis_status` is `SUCCESS`.
- `summary.json`: machine-readable status, hash verification result, total finding
  count, independent indicator count, severity, explicitly unvalidated score,
  warnings, errors, and limitations.
- `summary.txt`: compact key/value rendering of `summary.json` for human review.
- `yara.txt`: captured YARA stdout grouped by rule file.
- `strings.txt`: captured GNU strings stdout.

Statuses are `SUCCESS`, `PARTIAL`, `FAILED`, or `INTEGRITY_FAILURE`. A partial or
failed scan is not labelled clean, and its severity is `UNDETERMINED`.

The `unvalidated_triage_score` counts independent correlated indicator groups,
up to ten. It is retained for prototype continuity and is not a calibrated
probability.

## Evidence hashing

The pre-analysis SHA-256 identifies the bytes supplied to the scanner. The
post-analysis SHA-256 checks whether those bytes changed during analysis. A
mismatch produces `INTEGRITY_FAILURE`. Matching hashes do not establish
provenance, correct acquisition, or chain of custody.

## Path privacy

`manifest.json`, `findings.json`, raw YARA output, and recorded commands may
contain absolute local paths. The manifest also provides `input_file_display`
and `display_path` fields for contexts where workstation layout should not be
shared. Redaction is not automatic; analysts must review reports before
disclosure.

## Tests

```bash
source venv/bin/activate
python -m pytest -ra
```

The test fixtures under `tests/fixtures/` are inert text files. Test success
demonstrates expected prototype behavior for those controlled inputs, not
real-world detection performance.
