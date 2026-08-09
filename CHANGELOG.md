# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); versioning follows SemVer where
applicable, with alpha prereleases using `0.1.0aN`.

## [0.1.0a1] - 2026-08-09

### Added
- Package-owned implementation `cryptojacking_forensics` with a single `cj-triage` CLI.
- Subcommands: `scan artifact`, `doctor`, `rules check`, `verify-report`, `version`.
- In-process YARA scanning via `yara-python` (replaces PATH-resolved `yara` subprocess).
- Bounded, in-process string extractor (ASCII + UTF-16LE) replacing GNU `strings`.
- Versioned JSON schemas for manifest, summary, and findings.
- Stable exit-code contract (0/10/20/30/64/70); failed/partial scans no longer exit 0.
- Privacy-safe defaults: no raw strings or absolute paths unless `--raw` is set.
- Evidence integrity model with observed-control recording and no overclaimed guarantees.
- Governance files: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CODEOWNERS,
  issue/PR templates, threat model, safe-sample policy, release checklist,
  supported-platform policy.
- CI scaffolding (main, CodeQL, dependency/SBOM, release) and pre-commit config.

### Removed
- Tracked XMRig executable and archive from the source distribution.
- Windows-invalid tracked path `...` (stray Volatility error output).
- Orphaned subprocess-based modules (`commands.py`, `yara_scanner.py`).

### Fixed
- Exit code now reflects analysis status (was always 0).
- Evidence controls recorded as observed, not as constant "passed" values.

## [Unreleased pre-alpha]
- Academic prototype (prior history) — see git log.
