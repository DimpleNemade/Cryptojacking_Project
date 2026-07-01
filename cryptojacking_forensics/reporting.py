from __future__ import annotations

from pathlib import Path
from typing import Any

from .manifest import write_json


def write_summary_json(path: Path, summary: dict[str, Any]) -> None:
    write_json(path, summary)


def write_summary_text(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"CASE_ID={summary['case_id']}",
        f"RUN_ID={summary['run_id']}",
        f"ANALYSIS_STATUS={summary['analysis_status']}",
        f"HASH_VERIFICATION={summary['hash_verification']}",
        f"INPUT_SHA256_BEFORE={summary['input_sha256_before']}",
        f"INPUT_SHA256_AFTER={summary['input_sha256_after']}",
        f"FINDING_COUNT={summary['finding_count']}",
        f"INDEPENDENT_INDICATOR_COUNT={summary['independent_indicator_count']}",
        f"RISK_SEVERITY={summary['risk_severity']}",
        f"UNVALIDATED_TRIAGE_SCORE={summary['unvalidated_triage_score']}",
        f"EXPLANATION={summary['explanation']}",
        "WARNINGS=" + " | ".join(summary["warnings"]),
        "ERRORS=" + " | ".join(summary["errors"]),
        f"LIMITATIONS={summary['limitations']}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
