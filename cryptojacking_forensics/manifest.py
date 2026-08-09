"""Manifest assembly for a triage run.

Records OBSERVED evidence controls and tool/engine/rule versions. No field claims
more than was actually observed. See docs/LIMITATIONS.md for the boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .reporting import atomic_write_json, hash_file_sha256

SCHEMA_VERSION = "1.0.0"


@dataclass
class ManifestInput:
    case_id: str
    run_id: str
    started_at: str
    finished_at: str
    analysis_status: str
    evidence: dict[str, Any]
    engine: dict[str, Any]
    rule_pack: dict[str, Any]
    limits: dict[str, Any]
    stages: dict[str, str]
    warnings: list[str]
    errors: list[str]
    truncation: dict[str, Any]
    outputs: dict[str, Any]
    limitations: list[str]
    tool_name: str = "cryptojacking-forensics"
    tool_version: str = "0.1.0a1"


def build_manifest(m: ManifestInput) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": m.tool_name, "version": m.tool_version},
        "case_id": m.case_id,
        "run_id": m.run_id,
        "started_at": m.started_at,
        "finished_at": m.finished_at,
        "analysis_status": m.analysis_status,
        "evidence": m.evidence,
        "engine": m.engine,
        "rule_pack": m.rule_pack,
        "limits": m.limits,
        "stages": m.stages,
        "outputs": m.outputs,
        "warnings": m.warnings,
        "errors": m.errors,
        "truncation": m.truncation,
        "limitations": m.limitations,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    atomic_write_json(path, manifest)


def output_hashes(output_paths: list[Path]) -> list[dict[str, str]]:
    result = []
    for p in output_paths:
        if p.exists():
            result.append(
                {
                    "name": p.name,
                    "display_path": str(p),
                    "sha256": hash_file_sha256(p),
                }
            )
    return result
