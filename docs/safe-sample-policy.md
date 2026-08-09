# Safe Sample Handling Policy

This project follows a strict safe-sample policy.

## Prohibited in the source distribution
- Live miner binaries (e.g. XMRig), malware, or dual-use executables.
- Memory images, evidence dumps, or case data.
- Archives bundling the above.
- Large binaries that bloat the repository.

## What is allowed
- Inert synthetic text fixtures under `tests/fixtures/` (no executable content).
- Documentation-derived string snippets needed for rule design.
- Bundled YARA rules under `cryptojacking_forensics/rules/` (text only).

## Historical cleanup
On 2026-08-09 the tracked repository removed:
- the Windows-invalid path `...` (stray Volatility error output),
- the XMRig executable `Miner_Samples/xmrig-6.21.0/xmrig`,
- the archive `Miner_Samples/xmrig-6.21.0-linux-static-x64.tar.gz.1`,
- `SHA256SUMS` and `config.json` from that directory.

These remain in Git history. A history rewrite was **not** performed because it is
destructive and requires separate explicit owner approval. The current working tree
and all future commits no longer distribute them.

## Contribution rule
Never commit samples listed as prohibited. Real-world corpora belong in an
access-controlled, separately-governed location with documented provenance and
retention — not in this repository.
