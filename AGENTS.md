# Project Operating Instructions

## Scope and source of truth

- Work only inside this repository unless the user explicitly expands scope.
- Treat the Git repository root as the canonical local project. The excluded
  `Cryptojacking_Project-main/` directory is an extracted working copy, not the
  source of truth. Do not modify or cite it as delivered implementation unless
  the user explicitly asks to reconcile it.
- Reconcile material claims against the tracked implementation, the default
  branch on GitHub, and reproducible test evidence. An issue, roadmap checkbox,
  comment, or untracked file is not proof that a capability exists.
- Preserve unrelated user changes. Never restore, execute, or redistribute a
  quarantined sample merely to make the worktree clean.

## Evidence-first communication

- Be candid, critical, and professional. Do not inflate maturity, market value,
  detection coverage, forensic soundness, legal admissibility, or readiness.
- Separate statements into: observed fact, supported inference, proposed
  hypothesis, and target metric. Label inference and uncertainty explicitly.
- Prefer primary sources: project code and tests, upstream specifications,
  official documentation, standards bodies, vendor documentation for the
  vendor's own product, and original research. Record source URL and access date
  for time-sensitive research.
- Do not invent benchmarks, users, pilots, false-positive rates, coverage,
  revenue, legal acceptance, audit results, certifications, or independent
  validation. A target is never reported as an achieved result.
- Lead with the practical verdict and the evidence supporting it. Friendly
  conversation may contain opinion when invited; technical and market claims
  must remain evidence-based.

## Security and malware handling

- Treat every file under `Miner_Samples/`, every evidence image, every archive,
  and every extracted artifact as untrusted.
- Never execute miner or malware samples. Never import them as Python modules,
  load them into a host process, or open them with tools that can trigger active
  content. Inspect metadata and hashes only with safe, read-only workflows.
- Prefer inert synthetic fixtures for normal development and CI. Real samples
  belong in an access-controlled corpus outside ordinary source control, with
  documented provenance, licensing, retention, and handling procedures.
- Run parsers and scanners with least privilege, no unnecessary network access,
  explicit time and size limits, and isolated output directories. Treat
  filenames, YARA strings, tool output, and report fields as attacker-controlled
  data that must be escaped before display.
- Do not claim that opening a file with `rb`, checking `os.access`, or comparing
  pre/post hashes proves write protection, provenance, chain of custody, or
  legal admissibility. Those controls provide bounded technical evidence only.
- Fail closed when analysis is incomplete. A missing scanner, timeout, malformed
  rule, truncated input, output-write failure, or integrity mismatch must never
  be reported as a clean scan.

## Product boundaries

- Current scope is offline indicator triage over supplied files. The tracked
  code does not parse operating-system memory structures, attribute artifacts
  to processes, monitor runtime behavior, acquire evidence, or prove compromise.
- Use "memory forensics" only for features backed by a real memory-analysis
  engine and validated plugins. Otherwise say "file/artifact scanning."
- Use "forensic" carefully. The tool may support a forensic workflow, but the
  workflow, operator, acquisition process, environment, and validation evidence
  determine defensibility.
- The preferred product hypothesis is a narrow, offline, evidence-aware CLI
  that orchestrates proven scanning or memory-analysis engines and emits
  reproducible, explainable results. Do not expand into a hosted platform,
  endpoint agent, SIEM, EDR, RBAC system, or threat-sharing network without
  explicit user authorization and validated demand.

## Engineering expectations

- Maintain one package-owned implementation and one documented command. Legacy
  launchers may only be thin, tested compatibility wrappers.
- Define stable CLI contracts before adding features: commands, arguments,
  stdout/stderr behavior, exit codes, schemas, privacy defaults, limits, and
  backward-compatibility policy.
- Package with standards-based `pyproject.toml` metadata and a console-script
  entry point. Pin supported Python versions and declare runtime, optional, and
  development dependencies accurately.
- Prefer structured in-process APIs for scanners when they improve portability
  and error handling, but verify rule and result parity before migration. Record
  engine, package, rule-pack, and schema versions in every run manifest.
- Bound memory, output, scan duration, file count, and match count. Use atomic
  writes, deterministic ordering, restrictive output permissions where
  supported, and explicit handling for partial results.
- Verify third-party API units against upstream documentation. In particular,
  `yara-python` scan timeouts are whole seconds, not milliseconds.
- Never embed a hash of a finalized manifest inside that same manifest. Hash
  immutable sibling artifacts, write the manifest last, and verify paths remain
  within the report directory.
- Give every rule an owner, stable ID, version, purpose, supported input type,
  ATT&CK mapping where applicable, references, confidence rationale, and known
  false-positive conditions. Rule changes require positive, negative, boundary,
  and performance tests.
- Treat report schemas as public APIs. Version them, validate them with JSON
  Schema, and provide migrations or a documented compatibility policy.

## Validation and definition of done

- Run the smallest relevant tests while iterating and the complete supported
  suite before declaring work finished. If tests cannot run, report the exact
  reason and do not substitute historical results.
- A configured CI matrix is not evidence that a revision passed it. Record local
  and remote environments separately and cite an exact green commit/check run for
  remote platform claims.
- Test supported operating systems in clean environments. Mocked subprocess
  tests do not replace end-to-end tests with the actual supported engines.
- For detection claims, use a documented, versioned corpus with known labels,
  benign hard negatives, evasive variants, and held-out samples. Report the
  dataset, methodology, denominators, confidence intervals where appropriate,
  and limitations.
- Follow the SWGDE principle that an in-house tool influencing examination
  results should be tested by a competent person other than the developer,
  especially at first use and after revisions.
- A feature is done only when implementation, tests, failure behavior, security
  review, user documentation, migration notes, and acceptance evidence agree.
- Release claims must be no stronger than the available evidence. "Alpha"
  requires a clean install, stable CLI contract, supported-platform CI,
  documented limitations, safe sample handling, and repeatable end-to-end
  validation. "Production-ready," "enterprise-ready," and "court-ready" are
  prohibited without independently verifiable evidence and appropriate review.

## Repository hygiene and delivery

- Do not commit live miner binaries, malware, secrets, case evidence, reports,
  virtual environments, caches, or machine-specific paths.
- Require a license, `SECURITY.md`, contribution guidance, least-privilege CI,
  dependency review, an SBOM, and verifiable build provenance before publishing
  installable artifacts.
- Keep roadmap items outcome-based with an owner, dependencies, acceptance
  tests, exit gate, and evidence link. Dates are estimates, not promises.
- At handoff, state what was inspected, what changed, what was verified, what
  could not be verified, and any safety-relevant workspace state.
