# Supported Platform Policy

## Supported
- **Operating systems**: Windows 10+ and Ubuntu 22.04+ (validated in CI).
- **Python**: CPython 3.10, 3.11, 3.12.
- **Architecture**: x86-64.

## In-process engine
- `yara-python` >= 4.3, < 5 (wheels available for the supported matrix).

## Not yet supported / unverified
- macOS, other Linux distributions, ARM64: may work but are not CI-validated.
- Python < 3.10 or >= 3.13: untested.
- Any "memory forensics" claim: only via a real framework (e.g. Volatility 3) feeding
  structured output; not implemented in the alpha.

## Support commitment (alpha)
During the alpha phase, only the latest prerelease line is supported. Issues are
triaged best-effort. There is no SLA.
