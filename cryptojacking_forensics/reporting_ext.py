"""Summary assembly for a triage run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .findings import overall_evidence_strength
from .reporting import atomic_write_json

SCHEMA_VERSION = "1.0.0"


@dataclass
class SummaryInput:
    case_id: str
    run_id: str
    analysis_status: str
    hash_verification: str
    input_sha256_before: str | None
    input_sha256_after: str | None
    findings: list[Any]
    warnings: list[str]
    errors: list[str]
    limitations: list[str]


def build_summary(value: SummaryInput) -> dict[str, Any]:
    independent = sum(
        1 for finding in value.findings if getattr(finding, "independent_indicator", False)
    )
    strength = (
        overall_evidence_strength(value.findings)
        if value.analysis_status == "SUCCESS"
        else "UNDETERMINED"
    )
    if value.analysis_status == "SUCCESS" and not value.findings:
        explanation = "No configured indicators were found by the completed analyses."
    elif value.analysis_status == "SUCCESS":
        explanation = (
            f"{len(value.findings)} findings form {independent} independent indicator "
            "groups; analyst validation is required."
        )
    else:
        explanation = "Analysis incomplete; absence of findings must not be interpreted as clean."
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": value.case_id,
        "run_id": value.run_id,
        "analysis_status": value.analysis_status,
        "hash_verification": value.hash_verification,
        "input_sha256_before": value.input_sha256_before,
        "input_sha256_after": value.input_sha256_after,
        "finding_count": len(value.findings),
        "independent_indicator_count": independent,
        "evidence_strength": strength,
        "explanation": explanation,
        "warnings": value.warnings,
        "errors": value.errors,
        "limitations": value.limitations,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    atomic_write_json(path, summary)
