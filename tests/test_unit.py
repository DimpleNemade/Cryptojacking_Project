"""Unit tests: hashing, evidence model, case validation, strings extractor."""

from __future__ import annotations

from pathlib import Path

from cryptojacking_forensics.evidence import inspect_after, inspect_before
from cryptojacking_forensics.hashing import sha256_file, verify_hashes
from cryptojacking_forensics.strings_extractor import extract_strings


def test_sha256_deterministic(tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"cryptojacking test")
    assert sha256_file(p) == sha256_file(p)


def test_verify_hashes_pass_fail():
    assert verify_hashes("abc", "abc") == "PASS"
    assert verify_hashes("abc", "def") == "FAIL"
    assert verify_hashes("", "def") == "FAIL"


def test_inspect_before_reads_only(tmp_path: Path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"sample")
    rec = inspect_before(p)
    assert rec.opened_read_only is True
    assert rec.sha256_before is not None
    assert rec.hash_verification == "NOT_RUN"


def test_inspect_after_detects_unchanged(tmp_path: Path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"sample")
    rec = inspect_before(p)
    inspect_after(rec)
    assert rec.hash_verification == "PASS"
    assert rec.external_modification == "NONE"


def test_inspect_after_detects_change(tmp_path: Path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"sample")
    rec = inspect_before(p)
    p.write_bytes(b"sample-modified-content")
    inspect_after(rec)
    assert rec.hash_verification == "FAIL"
    assert rec.external_modification == "DETECTED"


def test_case_id_rejects_traversal():
    import pytest
    from cryptojacking_forensics.case import validate_case_id

    for bad in [".", "..", "../x", "has space", "", "a" * 65]:
        with pytest.raises(Exception):
            validate_case_id(bad)
    assert validate_case_id("CASE-001") == "CASE-001"


def test_strings_ascii_basic():
    data = b"hello world xmrig stratum+tcp://pool"
    res = extract_strings(data)
    assert "hello" in res.strings or "hello world xmrig stratum" in " ".join(res.strings)
    assert res.truncated is False


def test_strings_utf16le():
    data = "minerd.exe".encode("utf-16-le")
    res = extract_strings(data)
    assert any("minerd" in s for s in res.strings)


def test_strings_min_length_and_caps():
    data = b"ab cd ef gh ij kl mn op qr st uv wx yz aaabbbccc"
    res = extract_strings(data, min_length=4, max_strings=1, max_bytes=10)
    assert len(res.strings) <= 1
    assert res.truncated is True


def test_strings_deterministic_order():
    data = b"zzzfirst yyysecond xxxthird"
    a = extract_strings(data).strings
    b = extract_strings(data).strings
    assert a == b
