# ADR 0001: In-process scanning engine for the alpha

## Status
Accepted (2026-08-09).

## Context
The prototype invoked `yara` and GNU `strings` as external subprocesses resolved
from `PATH`. This creates four problems for an alpha deliverable:

1. **Portability**: the tool cannot run on a clean Windows host where neither
   binary is installed, and the version/identity of the binary is environment
   dependent.
2. **Forensic soundness**: the manifest tried to record the resolved engine path
   and hash, but a missing binary silently degrades to `PARTIAL`/failure with no
   deterministic behavior.
3. **Resource control**: unbounded `strings` output and `PATH`-resolved engines
   are hard to bound for memory and match counts.
4. **Reproducibility**: results depend on whatever `yara`/`strings` the operator
   happens to have, not a pinned, declared dependency.

We evaluated two maintained, in-process options against official documentation
and an install/test spike.

## Options considered

### yara-python (VirusTotal, classic bindings)
- Wheels available for Windows and Linux across CPython 3.10–3.12.
- Rule compatibility: identical YARA language to the CLI; compiles our existing
  `.yar` files unchanged.
- Structured match metadata: rule name, namespace, string identifier, offset,
  matched value via `CallbackMatches`.
- Timeout support: `timeout` parameter on `Rules.match`.
- Match limits: must be enforced by the caller in the match callback.
- Licensing: Apache-2.0 — compatible with our project license.
- Maintenance: actively maintained upstream.
- Process scanning: out of scope for this project (no live memory parsing in
  alpha); not a differentiator.

### YARA-X (VirusTotal, next generation)
- Cross-platform, Rust core, structured JSON results, file scan, match caps,
  timeouts.
- **Blocker for alpha**: as of evaluation, the official Python API wheel
  availability for Windows + the exact rule-parity with our existing classic
  rules was less certain, and the project's roadmap explicitly defers memory
  adapters. Classic `yara-python` gives a drop-in migration with no rule rewrites.

## Decision
Use **yara-python** as the supported in-process engine for the alpha. Replace the
`PATH`-resolved `yara` subprocess with `yara.Rules.compile` + `match` using a
match callback that enforces deadlines and match limits. Replace the GNU
`strings` subprocess with a bounded, in-process string extractor that supports
printable ASCII and UTF-16LE with configurable minimum length, byte/match caps,
and truncation reporting.

## Consequences
- The tool now installs and runs in a clean environment with only `pip install .`
  plus its declared dependency; no undocumented system executables required.
- Engine package and version are recorded in every manifest from a resolved
  import, not guessed from `PATH`.
- Future migration to YARA-X is possible by swapping the engine module behind the
  same interface; the rule pack stays in classic YARA for now.
- Strings extraction is intentionally limited to encodings relevant to the alpha
  and is bounded; it is not a substitute for full forensic string recovery.
