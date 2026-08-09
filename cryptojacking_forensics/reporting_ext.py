"""Summary assembly for a triage run.

Reports an evidence-strength summary, NOT a calibrated risk probability. The
unvalidated_triage_score is retained only as a bounded indicator-group count and is
explicitly not a risk model.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    unvalidated_triage_score: int | None


def build_summary(m: SummaryInput) -> dict[str, Any]:
    independent = sum(1 for f in m.findings if getattr(f, "independent_indicator", False))
    strength = overall_evidence_strength(m.findings) if m.analysis_status == "SUCCESS" else "UNDETERMINED"
    if m.analysis_status == "SUCCESS" and not m.findings:
        explanation = "No miner indicators were found by the completed triage analyses."
    elif m.analysis_status == "SUCCESS":
        explanation = (
            f"{len(m.findings)} triage findings were grouped into {independent} independent "
            "indicator groups; review findings.json."
        )
    else:
        explanation = "Analysis incomplete; absence of findings must not be interpreted as clean."
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": m.case_id,
        "run_id": m.run_id,
        "analysis_status": m.analysis_status,
        "hash_verification": m.hash_verification,
        "input_sha256_before": m.input_sha256_before,
        "input_sha256_after": m.input_sha256_after,
        "finding_count": len(m.findings),
        "independent_indicator_count": independent,
        "evidence_strength": strength,
        "explanation": explanation,
        "warnings": m.warnings,
        "errors": m.errors,
        "unvalidated_triage_score": m.unvalidated_triage_score,
        "limitations": m.limitations,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    atomic_write_json(path, summary)
