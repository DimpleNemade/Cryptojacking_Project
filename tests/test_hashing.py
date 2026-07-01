from pathlib import Path

from cryptojacking_forensics.evidence import inspect_after, inspect_before


def test_pre_and_post_hash_match(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"unchanged")
    record = inspect_before(evidence)
    inspect_after(record)
    assert record.sha256_before == record.sha256_after
    assert record.hash_verification == "PASS"


def test_pre_and_post_hash_mismatch(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"before")
    record = inspect_before(evidence)
    evidence.write_bytes(b"after")
    inspect_after(record)
    assert record.sha256_before != record.sha256_after
    assert record.hash_verification == "FAIL"

