"""In-process YARA scanning using yara-python.

Replaces the earlier PATH-resolved `yara` subprocess. See docs/adr/0001.
Engine identity and version come from the resolved import, not from a shell lookup.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

from .hashing import sha256_file

# yara-python exposes no clean __version__ on all builds; derive from the module.
ENGINE_NAME = "yara-python"
try:  # pragma: no cover - environment dependent
    ENGINE_VERSION = getattr(yara, "__version__", "unknown")
except Exception:  # pragma: no cover
    ENGINE_VERSION = "unknown"


class ScanError(Exception):
    """Raised when scanning cannot complete (engine failure, timeout, limit)."""


@dataclass
class Match:
    rule_id: str
    rule_name: str
    namespace: str
    string_id: str
    offset: int
    matched_value: str


@dataclass
class ScanResult:
    matches: list[Match] = field(default_factory=list)
    status: str = "SUCCESS"  # SUCCESS | PARTIAL | FAILED
    error: str | None = None
    truncated: bool = False
    match_count: int = 0


def compile_rules(rule_files: list[Path]) -> "yara.Rules":
    """Compile all bundled rules. Raises ScanError on failure with the reason."""
    if not rule_files:
        raise ScanError("no rule files provided")
    try:
        return yara.compile(
            filepaths={p.name: str(p) for p in rule_files},
            includes=False,
        )
    except yara.SyntaxError as exc:
        raise ScanError(f"rule compilation failed: {exc}") from exc
    except yara.Error as exc:
        raise ScanError(f"rule compilation failed: {exc}") from exc


def _rule_id_for(rule_name: str, meta: dict[str, Any]) -> str:
    rid = meta.get("rule_id")
    return str(rid) if rid else rule_name


def scan_bytes(
    rules: "yara.Rules",
    data: bytes,
    *,
    timeout_ms: int = 30_000,
    max_matches: int = 5_000,
) -> ScanResult:
    """Scan in-memory bytes. Enforces deadline and match cap; never reports
    timeout/engine failure as a clean result."""
    try:
        raw = rules.match(data=data, timeout=timeout_ms)
    except yara.TimeoutError:
        return ScanResult(status="FAILED", error="scan deadline exceeded", match_count=0)
    except yara.Error as exc:
        return ScanResult(status="FAILED", error=f"scan engine error: {exc}", match_count=0)

    collected: list[Match] = []
    truncated = False
    for rm in raw:
        rid = _rule_id_for(rm.rule, rm.meta)
        for s in rm.strings:
            for inst in s.instances:
                if len(collected) >= max_matches:
                    truncated = True
                    break
                collected.append(
                    Match(
                        rule_id=rid,
                        rule_name=rm.rule,
                        namespace=getattr(rm, "namespace", "") or "default",
                        string_id=s.identifier,
                        offset=inst.offset,
                        matched_value=inst.matched_data.decode("utf-8", "replace")[:200],
                    )
                )
            if truncated:
                break
        if truncated:
            break

    status = "PARTIAL" if truncated else "SUCCESS"
    return ScanResult(matches=collected, status=status, truncated=truncated, match_count=len(collected))


def rule_file_hashes(rule_files: list[Path]) -> tuple[str, list[dict[str, str]]]:
    """Return (canonical_pack_digest, per-file records)."""
    records = []
    digests = []
    for p in sorted(rule_files, key=lambda x: x.name):
        d = sha256_file(p)
        digests.append(d)
        records.append({"name": p.name, "sha256": d})
    import hashlib

    pack = hashlib.sha256("".join(digests).encode()).hexdigest()
    return pack, records
