# Contributing

Thanks for your interest in improving the Cryptojacking Forensic Triage tool.

## Ground rules

- This is an **alpha** research/education project. Honest scope and limitations
  are part of the product; do not overstate capabilities.
- One package-owned implementation (`cryptojacking_forensics`) and one primary
  command (`cj-triage`). Legacy launchers are thin wrappers only.
- Keep the forensic-integrity boundaries: never claim write protection, chain of
  custody, acquisition provenance, or legal admissibility.
- Do **not** commit live miner binaries, malware, secrets, case evidence, reports,
  virtual environments, or caches (see `.gitignore`).

## Development setup

```bash
python -m venv .venv
.venv/Scripts/activate        # or: source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -ra
```

A task runner is provided: `python tasks.py help`.

## Pull requests

- Target the default branch via a feature branch.
- Use Conventional Commits (`feat:`, `fix:`, `ci:`, `docs:`, `test:`, `refactor:`).
- Reference the related issue (e.g. `Closes #12`).
- Include tests for behavior changes; keep coverage on evidence/status/exit-code
  paths high.
- Do not mark an issue closed in the PR body unless acceptance criteria are met.

## What not to contribute

- GUI, hosted platform, endpoint agent, SIEM, EDR, RBAC service, REST platform,
  legal-reporting system, or threat-sharing network (out of scope per AGENTS.md).
- Any dual-use binary or sample that should live in an access-controlled corpus.
