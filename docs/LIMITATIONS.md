# Limitations

## Scope

This tool performs cryptojacking indicator triage over a supplied file. It does
not prove compromise by itself. YARA matches, extracted strings, wallet-format
candidates, pool or protocol indicators, and process-name indicators are leads
for analyst review.

The tool does not:

- acquire evidence;
- establish or manage chain of custody;
- parse operating-system memory structures;
- attribute extracted strings to running processes;
- provide a validated compromise probability;
- validate wallet checksums, ownership, activity, or network association; or
- establish that an observed indicator was executed or active on a host.

There is no process-aware memory analysis in the current repository. A matching
process name is therefore only a string or YARA-rule observation, not evidence
that a corresponding process was running.

## Detection limitations

- Wallet, mining-pool, process-name, port, and Stratum protocol indicators may
  occur in benign software, documentation, logs, configuration files, or test
  data and may therefore produce false positives.
- Obfuscated, encrypted, encoded, fragmented, compressed, novel, or absent
  indicators may not match the current rules and may produce false negatives.
- Rule quality and the behavior of the installed YARA and GNU strings tools
  directly affect results.
- Wallet matching is format-based candidate extraction only and is assigned low
  confidence. No checksum validation is implemented.
- Correlation groups repeated observations but cannot establish that grouped
  findings have a single real-world cause.
- `unvalidated_triage_score` is a count of independent correlated indicator
  groups, capped at ten. It is not a probability or a validated risk model.
- Synthetic fixtures test known strings and rules; they do not prove real-world
  detection performance.
- Absolute paths can appear in manifests, findings, raw output, and command
  records and may expose workstation layout. Display paths are provided, but
  redaction is not automatic.

Reports are not court-ready or legally determinative. Hash agreement supports
an integrity check over the analysis interval but does not prove provenance,
correct acquisition, chain of custody, or legal admissibility.

## Appropriate use

- Coursework and prototype validation.
- Forensic triage learning.
- Controlled lab analysis.
- Indicator scanning of supplied files.

## Inappropriate use

- Claiming confirmed compromise from this tool alone.
- Replacing analyst validation.
- Claiming legal admissibility.
- Using reports as final forensic conclusions without review.
