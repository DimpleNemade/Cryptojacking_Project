# Limitations

## Scope

This tool performs cryptojacking indicator triage over a supplied artifact. It does
not prove compromise by itself. YARA matches, extracted strings, wallet-format
candidates, pool or protocol indicators, and process-name indicators are leads for
analyst review.

The product is **not**:
- a memory-forensics framework by itself;
- an evidence-acquisition tool;
- a hardware write blocker;
- a chain-of-custody system;
- a runtime monitoring agent;
- a substitute for an EDR, SIEM, Falco, GuardDuty, or Defender;
- proof that a host was compromised;
- a legally determinative forensic instrument.

Use "file" or "artifact" for generic byte scanning. Use "memory forensics" only for
results obtained through a real memory-analysis framework such as Volatility 3.

The tool does not:
- acquire evidence;
- establish or manage chain of custody;
- parse operating-system memory structures;
- attribute extracted strings to running processes;
- provide a validated compromise probability;
- validate wallet checksums, ownership, activity, or network association; or
- establish that an observed indicator was executed or active on a host.

A matching process name is a string or YARA-rule observation, not evidence that a
corresponding process was running.

## Evidence-integrity boundaries (honest)

- Opening an input with `rb` does **not** prove the source is write-protected.
- `os.access` checks do **not** prove an ACL or hardware write-blocker guarantee.
- Pre/post SHA-256 agreement does **not** establish acquisition provenance or chain
  of custody. It only checks the bytes did not change during this tool's analysis.
- The software does **not** establish chain of custody.
- The output is **not** legally admissible. Admissibility is a legal/operational
  determination outside this tool's scope.
- The tool records *observed* control results; it does not insert constant "passed"
  values. A control that could not be evaluated is marked, not assumed true.

## Detection limitations

- Wallet, mining-pool, process-name, port, and Stratum protocol indicators may occur
  in benign software, documentation, logs, configuration files, or test data and may
  produce false positives.
- Obfuscated, encrypted, encoded, fragmented, compressed, novel, or absent indicators
  may not match the current rules and may produce false negatives.
- Rule quality and the behavior of the in-process `yara-python` engine affect results.
- Wallet matching is format-based candidate extraction only, assigned `LOW` confidence.
  No checksum validation is implemented.
- Correlation groups repeated observations but cannot establish a single real-world
  cause.
- Synthetic fixtures test known strings and rules; they do **not** prove real-world
  detection performance.
- Privacy-safe defaults omit raw strings and absolute paths; raw output is available
  only via explicit `--raw` opt-in, and redaction for disclosure remains the analyst's
  responsibility.
- SHA-256 representations of matched values are pseudonyms, not guaranteed
  anonymization. Common or low-entropy indicators may be recoverable by guessing and
  re-hashing; reports still require handling appropriate to the evidence context.

Findings are triage leads. They require analyst validation and must not be treated as
final forensic conclusions.
