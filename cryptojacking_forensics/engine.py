"""In-process YARA scanning using yara-python."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

from .hashing import sha256_file

ENGINE_NAME = "yara-python"
ENGINE_VERSION = str(getattr(yara, "__version__", "unknown"))
MAX_MATCHED_VALUE_CHARACTERS = 200


class ScanError(Exception):
    """Raised when YARA rules cannot be compiled."""


@dataclass(frozen=True)
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
    status: str = "SUCCESS"
    error: str | None = None
    truncated: bool = False
    match_count: int = 0


def compile_rules(rule_files: list[Path]) -> yara.Rules:
    if not rule_files:
        raise ScanError("no rule files provided")
    try:
        return yara.compile(
            filepaths={path.name: str(path) for path in rule_files},
            includes=False,
        )
    except (yara.SyntaxError, yara.Error) as exc:
        raise ScanError(f"rule compilation failed: {exc}") from exc


def _rule_id_for(rule_name: str, meta: dict[str, Any]) -> str:
    return str(meta.get("rule_id") or rule_name)


def _collect(raw_matches: list[Any], max_matches: int) -> ScanResult:
    collected: list[Match] = []
    for rule_match in raw_matches:
        rule_id = _rule_id_for(rule_match.rule, rule_match.meta)
        for string_match in rule_match.strings:
            for instance in string_match.instances:
                collected.append(
                    Match(
                        rule_id=rule_id,
                        rule_name=rule_match.rule,
                        namespace=getattr(rule_match, "namespace", "") or "default",
                        string_id=string_match.identifier,
                        offset=int(instance.offset),
                        matched_value=instance.matched_data.decode("utf-8", "replace")[
                            :MAX_MATCHED_VALUE_CHARACTERS
                        ],
                    )
                )

    collected.sort(
        key=lambda item: (
            item.offset,
            item.rule_id,
            item.rule_name,
            item.string_id,
            item.matched_value,
        )
    )
    truncated = len(collected) > max_matches
    collected = collected[:max_matches]
    return ScanResult(
        matches=collected,
        status="PARTIAL" if truncated else "SUCCESS",
        truncated=truncated,
        match_count=len(collected),
    )


def _run_match(
    rules: yara.Rules,
    *,
    timeout_seconds: float,
    max_matches: int,
    data: bytes | None = None,
    filepath: Path | None = None,
) -> ScanResult:
    if timeout_seconds <= 0:
        return ScanResult(status="FAILED", error="scan deadline exceeded")
    if max_matches < 1:
        return ScanResult(status="FAILED", error="max_matches must be positive")

    # yara-python documents timeout in whole seconds, not milliseconds.
    timeout = max(1, math.ceil(timeout_seconds))
    try:
        if filepath is not None:
            raw = rules.match(filepath=str(filepath), timeout=timeout)
        else:
            raw = rules.match(data=data, timeout=timeout)
    except yara.TimeoutError:
        return ScanResult(status="FAILED", error="scan deadline exceeded")
    except yara.Error as exc:
        return ScanResult(status="FAILED", error=f"scan engine error: {exc}")
    return _collect(raw, max_matches)


def scan_file(
    rules: yara.Rules,
    path: Path,
    *,
    timeout_seconds: float = 30.0,
    max_matches: int = 5_000,
) -> ScanResult:
    """Scan a file through YARA without first loading it into Python memory."""

    return _run_match(
        rules,
        filepath=path,
        timeout_seconds=timeout_seconds,
        max_matches=max_matches,
    )


def scan_bytes(
    rules: yara.Rules,
    data: bytes,
    *,
    timeout_seconds: float = 30.0,
    max_matches: int = 5_000,
) -> ScanResult:
    """Scan supplied bytes (primarily for tests and API callers)."""

    return _run_match(
        rules,
        data=data,
        timeout_seconds=timeout_seconds,
        max_matches=max_matches,
    )


def rule_file_hashes(rule_files: list[Path]) -> tuple[str, list[dict[str, str]]]:
    """Return a filename-sensitive canonical pack digest and per-file hashes."""

    records: list[dict[str, str]] = []
    digest = hashlib.sha256()
    for path in sorted(rule_files, key=lambda item: item.name):
        file_digest = sha256_file(path)
        records.append({"name": path.name, "sha256": file_digest})
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), records
