"""Strict schema-validation tests."""

from __future__ import annotations

from cryptojacking_forensics.reporting import load_schema, validate_document

SHA256 = "a" * 64


def test_schemas_exist_and_disallow_unknown_fields():
    for kind in ("manifest", "summary", "findings"):
        schema = load_schema(kind)
        assert schema["version"] == "1.0.0"
        assert schema["additionalProperties"] is False


def test_findings_valid_and_rejects_bad_strength():
    finding = {
        "finding_id": "F-0001",
        "finding_type": "YARA_RULE_MATCH",
        "source": "yara",
        "rule_id": "CJ-MINER-001",
        "rule_name": "rule",
        "matched_indicator": None,
        "matched_indicator_sha256": SHA256,
        "offset": 12,
        "evidence_strength": "MEDIUM",
        "confidence": "MEDIUM",
        "explanation": "matched",
        "evidence_reference": "e.bin",
        "finding_group_id": "G-0001",
        "corroborates_finding_id": None,
        "independent_indicator": True,
        "correlation_note": "primary",
        "limitations": "analyst validation required",
    }
    document = {"schema_version": "1.0.0", "findings": [finding]}
    assert validate_document("findings", document)[0]
    finding["evidence_strength"] = "IMPOSSIBLE"
    assert not validate_document("findings", document)[0]


def test_summary_requires_complete_contract():
    document = {
        "schema_version": "1.0.0",
        "case_id": "CASE-1",
        "run_id": "run-1",
        "analysis_status": "SUCCESS",
        "hash_verification": "PASS",
        "input_sha256_before": SHA256,
        "input_sha256_after": SHA256,
        "finding_count": 0,
        "independent_indicator_count": 0,
        "evidence_strength": "NONE",
        "explanation": "complete",
        "warnings": [],
        "errors": [],
        "limitations": ["limited"],
    }
    assert validate_document("summary", document)[0]
    document["unknown"] = True
    assert not validate_document("summary", document)[0]


def test_manifest_rejects_missing_required():
    valid, errors = validate_document("manifest", {"schema_version": "1.0.0"})
    assert not valid
    assert errors
