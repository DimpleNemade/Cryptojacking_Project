# Release Checklist

Use this for every alpha/prerelease.

## Pre-release
- [ ] `python -m pytest -ra` passes on the default branch (Ubuntu + Windows in CI).
- [ ] `cj-triage doctor`, `cj-triage rules check`, `cj-triage verify-report` work.
- [ ] Wheel builds and installs in a clean environment outside the source tree.
- [ ] `cj-triage` runs a synthetic fixture scan from the clean install (exit 10).
- [ ] CodeQL and dependency workflows are operational.
- [ ] SBOM generated and attached.
- [ ] README commands executed and verified.
- [ ] No live miner/malware binaries, no invalid Windows path in the tree.
- [ ] LICENSE, SECURITY.md, CONTRIBUTING.md, governance templates present.
- [ ] Validation doc updated with actual environment, commands, and results.

## Release
- [ ] Tag `v0.1.0-alpha.N` created.
- [ ] GitHub prerelease created from the tag with wheel, sdist, checksums, SBOM.
- [ ] Provenance/attestation attached where GitHub supports it.
- [ ] Not published to PyPI without explicit authorization.

## Post-release
- [ ] Changelog updated.
- [ ] Issues closed only where acceptance criteria are met with evidence.
