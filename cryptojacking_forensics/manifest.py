"""Manifest assembly for a triage run."""

from __future__ import annotations

from dataclasses import dataclass
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
    tool_version: str = "0.1.0a2"


def build_manifest(value: ManifestInput) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": value.tool_name, "version": value.tool_version},
        "case_id": value.case_id,
        "run_id": value.run_id,
        "started_at": value.started_at,
        "finished_at": value.finished_at,
        "analysis_status": value.analysis_status,
        "evidence": value.evidence,
        "engine": value.engine,
        "rule_pack": value.rule_pack,
        "limits": value.limits,
        "stages": value.stages,
        "outputs": value.outputs,
        "warnings": value.warnings,
        "errors": value.errors,
        "truncation": value.truncation,
        "limitations": value.limitations,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    atomic_write_json(path, manifest)


def output_hashes(output_paths: list[Path]) -> list[dict[str, str]]:
    """Hash immutable sibling artifacts; the manifest never hashes itself."""

    return [
        {"name": path.name, "sha256": hash_file_sha256(path)}
        for path in sorted(output_paths, key=lambda item: item.name)
        if path.is_file()
    ]
