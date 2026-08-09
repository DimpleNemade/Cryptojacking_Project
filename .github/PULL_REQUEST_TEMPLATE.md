# Pull request

## Summary
<!-- What changes and why. -->

## Scope
- [ ] Offline triage scope only (no GUI/SIEM/EDR/agent/platform).
- [ ] No live malware, miner binaries, credentials, or evidence committed.
- [ ] Tests added/updated; `python -m pytest -ra` passes locally.
- [ ] Documentation updated if behavior changed.
- [ ] No overstated forensic/legal claims.

## Related issue
Closes #<number>

## Validation
<!-- Commands run and results. -->
- `python -m pytest -ra`
- `cj-triage doctor`
- `cj-triage rules check`
