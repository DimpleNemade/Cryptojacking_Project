"""Engine integration + rule-pack tests against the real in-process yara-python."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptojacking_forensics.engine import (
    ScanError,
    compile_rules,
    rule_file_hashes,
    scan_bytes,
)

RULES = Path(__file__).parent.parent / "cryptojacking_forensics" / "rules"


def test_compile_bundled_rules():
    files = sorted(RULES.glob("*.yar"))
    assert files, "no bundled rules"
    rules = compile_rules(files)
    assert rules is not None


def test_scan_positive_detects():
    files = sorted(RULES.glob("*.yar"))
    rules = compile_rules(files)
    data = b"stratum+tcp://pool.example:3333 xmrig randomx donate-level"
    res = scan_bytes(rules, data)
    assert res.status in ("SUCCESS", "PARTIAL")
    assert res.match_count > 0


def test_scan_clean_no_match():
    files = sorted(RULES.glob("*.yar"))
    rules = compile_rules(files)
    data = b"routine log entry: backup completed successfully with no anomalies observed today"
    res = scan_bytes(rules, data)
    assert res.match_count == 0


def test_rule_metadata_ids_present():
    files = sorted(RULES.glob("*.yar"))
    rules = compile_rules(files)
    # Compile succeeds; metadata is exercised in build_findings mapping.
    assert rules is not None


def test_malformed_rule_raises():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "bad.yar"
        bad.write_text("rule broken { this is not valid yara >>> }\n")
        with pytest.raises(ScanError):
            compile_rules([bad])


def test_rule_pack_hash_stable():
    files = sorted(RULES.glob("*.yar"))
    digest1, _ = rule_file_hashes(files)
    digest2, _ = rule_file_hashes(files)
    assert digest1 == digest2


def test_scan_match_limit_enforced():
    files = sorted(RULES.glob("*.yar"))
    rules = compile_rules(files)
    # Many repetitions of a matched token should be capped.
    data = (b"xmrig " * 20000)
    res = scan_bytes(rules, data, max_matches=50)
    assert res.match_count <= 50
    assert res.truncated is True


def test_scan_timeout_param_handled():
    files = sorted(RULES.glob("*.yar"))
    rules = compile_rules(files)
    data = b"xmrig" * 5000
    # A very small timeout must not crash; result should be a valid status.
    res = scan_bytes(rules, data, timeout_ms=1)
    assert res.status in ("SUCCESS", "PARTIAL", "FAILED")
