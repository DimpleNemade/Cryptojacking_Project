"""Schema validation tests for manifest, summary, and findings."""

from __future__ import annotations

import json
from pathlib import Path

from cryptojacking_forensics.reporting import load_schema, validate_document

SCHEMA_DIR = Path(__file__).parent.parent / "cryptojacking_forensics" / "schemas"


def test_schemas_exist():
    for kind in ("manifest", "summary", "findings"):
        assert load_schema(kind)["version"] == "1.0.0"


def test_manifest_valid_example():
    doc = {
        "schema_version": "1.0.0",
        "tool": {"name": "cryptojacking-forensics", "version": "0.1.0a1"},
        "case_id": "CASE-1",
        "run_id": "run-1",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "analysis_status": "SUCCESS",
        "evidence": {
            "input_file_display": "e.bin",
            "sha256_before": "abc",
            "hash_verification": "PASS",
        },
        "engine": {"name": "yara-python", "version": "4.5.4"},
        "rule_pack": {"name": "x", "version": "1.0.0", "digest": "deadbeef"},
        "limits": {"max_matches": 5000},
        "stages": {"scan": "SUCCESS"},
        "outputs": {"privacy_mode": "safe"},
        "warnings": [],
        "errors": [],
        "truncation": {},
        "limitations": ["lim"],
    }
    ok, errs = validate_document("manifest", doc)
    assert ok, errs


def test_manifest_rejects_missing_required():
    doc = {"schema_version": "1.0.0"}
    ok, errs = validate_document("manifest", doc)
    assert not ok
    assert errs


def test_summary_valid_example():
    doc = {
        "schema_version": "1.0.0",
        "case_id": "CASE-1",
        "run_id": "run-1",
        "analysis_status": "SUCCESS",
        "hash_verification": "PASS",
        "evidence_strength": "MEDIUM",
        "warnings": [],
        "errors": [],
        "limitations": ["lim"],
    }
    ok, errs = validate_document("summary", doc)
    assert ok, errs


def test_findings_valid_example():
    doc = [
        {
            "finding_id": "F-0001",
            "finding_type": "YARA_RULE_MATCH",
            "source": "yara",
            "rule_id": "CJ-MINER-001",
            "rule_name": "cj_miner_xmrig_config_1",
            "matched_indicator": "donate-level",
            "offset": 12,
            "evidence_strength": "MEDIUM",
            "confidence": "MEDIUM",
            "explanation": "x",
            "evidence_reference": "e.bin",
            "finding_group_id": "G-0001",
            "corroborates_finding_id": None,
            "independent_indicator": True,
            "correlation_note": "primary",
            "limitations": "lim",
        }
    ]
    ok, errs = validate_document("findings", doc)
    assert ok, errs


def test_findings_rejects_bad_strength():
    doc = [{"finding_id": "F-1", "finding_type": "X", "source": "yara",
            "evidence_strength": "IMPOSSIBLE", "confidence": "LOW",
            "corroborates_finding_id": None, "independent_indicator": True,
            "limitations": "lim"}]
    ok, _ = validate_document("findings", doc)
    assert not ok
