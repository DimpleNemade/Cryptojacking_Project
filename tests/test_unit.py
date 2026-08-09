"""Hashing, evidence identity, and bounded string extraction tests."""

from __future__ import annotations

from pathlib import Path

from cryptojacking_forensics.evidence import inspect_after, inspect_before
from cryptojacking_forensics.hashing import sha256_file, verify_hashes
from cryptojacking_forensics.strings_extractor import extract_strings, extract_strings_file


def test_hashing_pass_and_fail(tmp_path: Path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"cryptojacking test")
    digest = sha256_file(path)
    assert digest == sha256_file(path)
    assert verify_hashes(digest, digest) == "PASS"
    assert verify_hashes(digest, "0" * 64) == "FAIL"


def test_evidence_before_after_identity(tmp_path: Path):
    path = tmp_path / "e.bin"
    path.write_bytes(b"sample")
    record = inspect_before(path)
    assert record.opened_read_only is True
    inspect_after(record)
    assert record.hash_verification == "PASS"
    assert record.external_modification == "NONE"
    assert record.stat_inode_before == record.stat_inode_after


def test_evidence_change_fails_integrity(tmp_path: Path):
    path = tmp_path / "e.bin"
    path.write_bytes(b"sample")
    record = inspect_before(path)
    path.write_bytes(b"changed content")
    inspect_after(record)
    assert record.hash_verification == "FAIL"
    assert record.external_modification == "DETECTED"


def test_strings_ascii_utf16_offsets_and_file_api(tmp_path: Path):
    data = b"xx\x00xmrig\x00" + "minerd.exe".encode("utf-16-le")
    result = extract_strings(data, min_length=4)
    ascii_entry = next(entry for entry in result.entries if entry.value == "xmrig")
    utf_entry = next(entry for entry in result.entries if "minerd.exe" in entry.value)
    assert ascii_entry.offset == 3
    assert utf_entry.encoding == "utf-16le"
    path = tmp_path / "odd.bin"
    path.write_bytes(data + b"x")
    assert extract_strings_file(path).strings == extract_strings(data + b"x").strings


def test_strings_caps_single_long_value_without_large_output():
    result = extract_strings(b"A" * 100_000, max_string_bytes=128, max_bytes=256)
    assert len(result.strings) == 1
    assert len(result.strings[0]) == 128
    assert result.truncated is True
    assert result.emitted_bytes == 128


def test_strings_count_cap_is_deterministic():
    data = b"first\x00second\x00third"
    first = extract_strings(data, max_strings=2)
    second = extract_strings(data, max_strings=2)
    assert first.entries == second.entries
    assert len(first.entries) == 2
    assert first.truncated is True
