# Alpha Release Checklist

## Verified locally for 0.1.0a2 on 2026-08-10

- [x] Lint and pre-commit hooks pass.
- [x] 46 tests pass at 85.35% statement coverage with the 85% gate.
- [x] `doctor`, `rules check`, and bundle verification pass.
- [x] Wheel and source distribution build from standards-based metadata.
- [x] Wheel installs in a clean environment outside the source tree.
- [x] Installed CLI returns `10` for the inert positive fixture and verifies its bundle.
- [x] Source distribution contains governance/docs/fixtures and no miner binary.
- [x] Local CycloneDX 1.6 SBOM generation and validation pass for the clean wheel environment.
- [x] README and validation record match reproduced behavior.

## Remote release gates

- [ ] Exact commit passes required Windows/Ubuntu, Python 3.10-3.12 CI jobs.
- [ ] CodeQL, dependency review, pre-commit, and SBOM workflows pass.
- [ ] `main` branch protection/ruleset is enabled and tested with a pull request.
- [ ] Release build produces wheel, sdist, checksums, SBOM, and provenance attestation.
- [ ] GitHub prerelease is created from `v0.1.0-alpha.2`.

Do not publish to PyPI without explicit authorization. Do not mark remote gates
complete from workflow YAML alone.

## Validity gates intentionally not claimed

- Independent competent-person validation.
- Versioned representative corpus and measured detection performance.
- External operator pilot or validated demand.
- Production, enterprise, or court readiness.
