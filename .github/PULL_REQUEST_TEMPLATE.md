# Pull request

## Summary
<!-- What changes and why. -->

## Scope
- [ ] Offline triage scope only (no GUI/SIEM/EDR/agent/platform).
- [ ] No live malware, miner binaries, credentials, or evidence committed.
- [ ] Tests added/updated; the supported lint, coverage, and pre-commit gates pass locally.
- [ ] User-visible behavior and compatibility impact are described below.
- [ ] Documentation and migration notes are updated when behavior or schemas change.
- [ ] Security and privacy impact is assessed, including attacker-controlled output handling.
- [ ] Evidence-integrity and fail-closed behavior is preserved or the risk is documented.
- [ ] Dependency changes are justified; lock/metadata, dependency review, and SBOM impact are addressed.
- [ ] No overstated forensic/legal claims.

## Related issue
Closes #<number>

## Validation
<!-- Commands run and results. -->
- `python -m ruff check cryptojacking_forensics tests tasks.py`
- `python -m pytest --cov=cryptojacking_forensics --cov-fail-under=85`
- `python -m pre_commit run --all-files --show-diff-on-failure`
- `cj-triage doctor`
- `cj-triage rules check`

## Impact notes
<!-- State "none" with a reason when a category does not apply. -->

- User-visible or compatibility impact:
- Security and privacy impact:
- Evidence-integrity impact:
- Dependency or SBOM impact:
