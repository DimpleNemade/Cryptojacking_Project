"""Failure-state and deterministic-correlation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptojacking_forensics import cli
from cryptojacking_forensics.cli import EXIT_PARTIAL
from cryptojacking_forensics.findings import build_findings, overall_evidence_strength
from cryptojacking_forensics.strings_extractor import extract_strings


def test_oversized_input_writes_failed_report(tmp_path: Path):
    artifact = tmp_path / "small.bin"
    artifact.write_bytes(b"xmrig stratum" * 10)
    saved = cli.DEFAULT_LIMITS
    cli.DEFAULT_LIMITS = {**saved, "max_input_bytes": 5}
    try:
        result = cli.main(
            [
                "scan",
                "artifact",
                str(artifact),
                "--case-id",
                "SML",
                "--output",
                str(tmp_path / "reports"),
            ]
        )
    finally:
        cli.DEFAULT_LIMITS = saved
    assert result == EXIT_PARTIAL
    summary_path = next((tmp_path / "reports" / "SML").glob("*/summary.json"))
    summary = json.loads(summary_path.read_text())
    assert summary["analysis_status"] == "FAILED"
    assert summary["evidence_strength"] == "UNDETERMINED"
    assert summary["errors"]


def test_correlation_is_content_order_independent():
    first = {
        "rule_id": "CJ-MINER-001",
        "rule_name": "a",
        "source": "yara",
        "matched_indicator": "donate-level",
        "offset": 7,
    }
    second = {
        "rule_id": "CJ-PROC-001",
        "rule_name": "b",
        "source": "yara",
        "matched_indicator": "xmrig",
        "offset": 2,
    }
    strings = extract_strings(b"xmrig stratum+tcp://pool:3333")
    left = [finding.to_dict() for finding in build_findings([first, second], strings, "e.bin")]
    right = [finding.to_dict() for finding in build_findings([second, first], strings, "e.bin")]
    assert left == right
    assert all(item["matched_indicator"] is None for item in left)
    assert any(not item["independent_indicator"] for item in left)


def test_overall_evidence_strength():
    empty = build_findings([], extract_strings(b"ordinary text"), "e.bin")
    assert overall_evidence_strength(empty) == "NONE"
    findings = build_findings(
        [
            {
                "rule_id": "CJ-MINER-001",
                "rule_name": "a",
                "source": "yara",
                "matched_indicator": "x",
                "offset": 1,
            }
        ],
        extract_strings(b"ordinary text"),
        "e.bin",
    )
    assert overall_evidence_strength(findings) == "MEDIUM"


@pytest.mark.parametrize("case_id", ["", "..", "../x", "a" * 65, "has space"])
def test_unsafe_case_ids_rejected(tmp_path: Path, case_id: str):
    result = cli.main(
        [
            "scan",
            "artifact",
            str(tmp_path / "missing"),
            "--case-id",
            case_id,
            "--output",
            str(tmp_path / "reports"),
        ]
    )
    assert result == cli.EXIT_USAGE
