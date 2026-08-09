"""Evidence handling and integrity model.

Implements technically defensible controls WITHOUT overstating them.
Observed controls are recorded; no constant "passed" values are inserted. We do
NOT claim write protection, acquisition provenance, or chain of custody (see
AGENTS.md and docs/LIMITATIONS.md).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .hashing import sha256_file, verify_hashes


@dataclass
class EvidenceRecord:
    path: Path
    display_name: str
    size: int | None = None
    sha256_before: str | None = None
    sha256_after: str | None = None
    hash_verification: str = "NOT_RUN"
    opened_read_only: bool = False
    accessed_at: str | None = None
    stat_mtime_before: float = 0.0
    stat_size_before: int = 0
    stat_device_before: int = 0
    stat_inode_before: int = 0
    stat_mtime_after: float | None = None
    stat_size_after: int | None = None
    stat_device_after: int | None = None
    stat_inode_after: int | None = None
    external_modification: str = "NOT_CHECKED"
    observed_controls: list[str] = field(default_factory=list)
    control_limitations: list[str] = field(default_factory=list)
    access_log: list[str] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def inspect_before(path: Path) -> EvidenceRecord:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"input evidence is not a regular file: {resolved}")

    opened_read_only = False
    try:
        with open(resolved, "rb") as fh:
            fh.read(1)
        opened_read_only = True
    except OSError as exc:
        raise OSError(f"could not open evidence read-only: {exc}") from exc

    stat = resolved.stat()
    record = EvidenceRecord(
        resolved,
        resolved.name,
        stat.st_size,
        sha256_file(resolved),
        opened_read_only=opened_read_only,
        accessed_at=_now(),
        stat_mtime_before=stat.st_mtime,
        stat_size_before=stat.st_size,
        stat_device_before=stat.st_dev,
        stat_inode_before=stat.st_ino,
    )
    record.observed_controls.append("opened input read-only (rb)")
    record.observed_controls.append("read input byte content for SHA-256")
    record.control_limitations.append(
        "Opening read-only proves only this open was not a write open; it does not "
        "establish OS-level write blocking or acquisition provenance."
    )
    record.access_log.append(f"{record.accessed_at} OPEN read-only {resolved.name}")
    return record


def inspect_after(record: EvidenceRecord) -> EvidenceRecord:
    if record.sha256_before is None:
        raise ValueError("pre-analysis SHA-256 is unavailable")
    record.sha256_after = sha256_file(record.path)
    record.hash_verification = verify_hashes(record.sha256_before, record.sha256_after)
    stat = record.path.stat()
    record.stat_mtime_after = stat.st_mtime
    record.stat_size_after = stat.st_size
    record.stat_device_after = stat.st_dev
    record.stat_inode_after = stat.st_ino
    changed = (
        record.stat_size_after != record.stat_size_before
        or record.stat_mtime_after != record.stat_mtime_before
        or record.stat_device_after != record.stat_device_before
        or record.stat_inode_after != record.stat_inode_before
    )
    if changed:
        record.external_modification = "DETECTED"
        record.observed_controls.append("post-analysis stat shows identity, size, or mtime change")
        record.hash_verification = "FAIL"
    else:
        record.external_modification = "NONE"
    record.access_log.append(f"{_now()} CLOSE {record.path.name}")
    return record


def write_access_advisory(record: EvidenceRecord) -> None:
    """Record (not enforce) whether the process appears able to write the input.

    os.access is advisory, platform-dependent, and subject to TOCTOU. We record the
    observation and explicitly state it is not a guarantee.
    """
    try:
        writable = os.access(record.path, os.W_OK)
    except OSError:
        writable = False
    record.observed_controls.append(
        f"os.access(W_OK)={writable} (advisory only; not a write-blocker guarantee)"
    )
    record.control_limitations.append(
        "os.access is advisory and time-of-check dependent; it does not prove a "
        "hardware or OS write block was applied during acquisition."
    )
