"""Tests against the real in-process yara-python engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptojacking_forensics.engine import (
    ScanError,
    compile_rules,
    rule_file_hashes,
    scan_bytes,
    scan_file,
)

RULES = Path(__file__).parent.parent / "cryptojacking_forensics" / "rules"


def _rules():
    return compile_rules(sorted(RULES.glob("*.yar")))


def test_compile_and_scan_file(tmp_path: Path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"stratum+tcp://pool.example:3333 xmrig randomx donate-level")
    result = scan_file(_rules(), artifact, timeout_seconds=2)
    assert result.status in {"SUCCESS", "PARTIAL"}
    assert result.match_count > 0
    assert result.matches == sorted(
        result.matches,
        key=lambda item: (
            item.offset,
            item.rule_id,
            item.rule_name,
            item.string_id,
            item.matched_value,
        ),
    )


def test_scan_clean_and_invalid_timeout():
    clean = scan_bytes(_rules(), b"routine backup completed", timeout_seconds=2)
    assert clean.status == "SUCCESS"
    assert clean.match_count == 0
    expired = scan_bytes(_rules(), b"xmrig", timeout_seconds=0)
    assert expired.status == "FAILED"
    assert "deadline" in (expired.error or "")


def test_malformed_rule_raises(tmp_path: Path):
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { this is not valid yara >>> }\n")
    with pytest.raises(ScanError):
        compile_rules([bad])


def test_rule_pack_hash_is_stable_and_filename_sensitive(tmp_path: Path):
    files = sorted(RULES.glob("*.yar"))
    digest, records = rule_file_hashes(files)
    assert digest == rule_file_hashes(files)[0]
    assert len(records) == len(files)
    first = tmp_path / "renamed.yar"
    first.write_bytes(files[0].read_bytes())
    assert rule_file_hashes([first])[0] != rule_file_hashes([files[0]])[0]


def test_match_limit_is_fail_closed_partial():
    result = scan_bytes(_rules(), b"xmrig " * 20_000, max_matches=50)
    assert result.match_count == 50
    assert result.truncated is True
    assert result.status == "PARTIAL"


def test_rule_pack_metadata_contract():
    document = json.loads((RULES / "rule_pack.json").read_text())
    records = document["rule_pack"]["rules"]
    required = {
        "rule_id",
        "file",
        "name",
        "version",
        "purpose",
        "input_type",
        "mitre",
        "references",
        "confidence",
        "false_positives",
        "reviewed",
    }
    assert records
    assert all(required <= set(record) for record in records)
    assert len({record["rule_id"] for record in records}) == len(records)
    assert all((RULES / record["file"]).is_file() for record in records)
    observed = {
        match.rule_id
        for match in scan_bytes(
            _rules(), b"xmrig stratum+tcp://pool:3333 randomx donate-level"
        ).matches
    }
    assert observed <= {record["rule_id"] for record in records}
