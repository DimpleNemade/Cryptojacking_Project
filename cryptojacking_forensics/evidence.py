from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .hashing import sha256_file, verify_hashes


@dataclass
class EvidenceRecord:
    path: Path
    size: int
    sha256_before: str
    sha256_after: str | None = None
    hash_verification: str = "NOT_RUN"


def inspect_before(path: Path) -> EvidenceRecord:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"input evidence is not a regular file: {resolved}")
    stat = resolved.stat()
    return EvidenceRecord(resolved, stat.st_size, sha256_file(resolved))


def inspect_after(record: EvidenceRecord) -> EvidenceRecord:
    record.sha256_after = sha256_file(record.path)
    record.hash_verification = verify_hashes(
        record.sha256_before, record.sha256_after
    )
    return record

