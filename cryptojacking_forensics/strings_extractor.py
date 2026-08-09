"""Bounded, streaming extraction of printable ASCII and UTF-16LE strings."""

from __future__ import annotations

import io
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class ExtractionTimeout(RuntimeError):
    """Raised when the shared analysis deadline expires."""


@dataclass(frozen=True)
class ExtractedString:
    value: str
    offset: int
    encoding: str
    value_truncated: bool = False


@dataclass
class StringResult:
    entries: list[ExtractedString]
    truncated: bool = False
    emitted_bytes: int = 0
    total_found: int = 0

    @property
    def strings(self) -> list[str]:
        """Compatibility view used by callers that only need values."""
        return [entry.value for entry in self.entries]


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise ExtractionTimeout("string extraction deadline exceeded")


def _emit_run(
    results: list[ExtractedString],
    buffer: bytearray,
    run_length: int,
    start: int,
    encoding: str,
    min_length: int,
    value_truncated: bool,
) -> None:
    if run_length < min_length:
        return
    if encoding == "utf-16le":
        value = bytes(buffer).decode("ascii", "replace")
    else:
        value = bytes(buffer).decode("ascii", "replace")
    results.append(ExtractedString(value, start, encoding, value_truncated))


def _scan_ascii(
    stream: BinaryIO,
    *,
    min_length: int,
    candidate_limit: int,
    max_string_bytes: int,
    deadline: float | None,
    chunk_size: int,
) -> list[ExtractedString]:
    results: list[ExtractedString] = []
    buffer = bytearray()
    run_start = 0
    run_length = 0
    offset = 0
    value_truncated = False

    while True:
        _check_deadline(deadline)
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        for value in chunk:
            if 0x20 <= value <= 0x7E:
                if run_length == 0:
                    run_start = offset
                run_length += 1
                if len(buffer) < max_string_bytes:
                    buffer.append(value)
                else:
                    value_truncated = True
            else:
                _emit_run(
                    results,
                    buffer,
                    run_length,
                    run_start,
                    "ascii",
                    min_length,
                    value_truncated,
                )
                if len(results) >= candidate_limit:
                    return results
                buffer.clear()
                run_length = 0
                value_truncated = False
            offset += 1

    _emit_run(
        results,
        buffer,
        run_length,
        run_start,
        "ascii",
        min_length,
        value_truncated,
    )
    return results


def _scan_utf16le(
    stream: BinaryIO,
    *,
    alignment: int,
    min_length: int,
    candidate_limit: int,
    max_string_bytes: int,
    deadline: float | None,
    chunk_size: int,
) -> list[ExtractedString]:
    results: list[ExtractedString] = []
    buffer = bytearray()
    run_start = alignment
    run_length = 0
    value_truncated = False
    absolute = alignment
    carry = b""
    stream.seek(alignment)

    while True:
        _check_deadline(deadline)
        incoming = stream.read(chunk_size)
        if not incoming:
            break
        chunk = carry + incoming
        usable = len(chunk) - (len(chunk) % 2)
        carry = chunk[usable:]
        for index in range(0, usable, 2):
            low, high = chunk[index], chunk[index + 1]
            if 0x20 <= low <= 0x7E and high == 0:
                if run_length == 0:
                    run_start = absolute
                run_length += 1
                if len(buffer) < max_string_bytes:
                    buffer.append(low)
                else:
                    value_truncated = True
            else:
                _emit_run(
                    results,
                    buffer,
                    run_length,
                    run_start,
                    "utf-16le",
                    min_length,
                    value_truncated,
                )
                if len(results) >= candidate_limit:
                    return results
                buffer.clear()
                run_length = 0
                value_truncated = False
            absolute += 2

    _emit_run(
        results,
        buffer,
        run_length,
        run_start,
        "utf-16le",
        min_length,
        value_truncated,
    )
    return results


def _extract(
    opener: Callable[[], BinaryIO],
    *,
    min_length: int,
    max_strings: int,
    max_bytes: int,
    max_string_bytes: int,
    deadline: float | None,
    chunk_size: int,
) -> StringResult:
    if min_length < 1:
        raise ValueError("min_length must be positive")
    if min(max_strings, max_bytes, max_string_bytes, chunk_size) < 1:
        raise ValueError("string extraction limits must be positive")

    # One extra candidate makes truncation observable without unbounded storage.
    candidate_limit = max_strings + 1
    with opener() as stream:
        candidates = _scan_ascii(
            stream,
            min_length=min_length,
            candidate_limit=candidate_limit,
            max_string_bytes=max_string_bytes,
            deadline=deadline,
            chunk_size=chunk_size,
        )
    for alignment in (0, 1):
        if len(candidates) >= candidate_limit:
            break
        with opener() as stream:
            candidates.extend(
                _scan_utf16le(
                    stream,
                    alignment=alignment,
                    min_length=min_length,
                    candidate_limit=candidate_limit - len(candidates),
                    max_string_bytes=max_string_bytes,
                    deadline=deadline,
                    chunk_size=chunk_size,
                )
            )

    candidates.sort(key=lambda item: (item.offset, item.encoding, item.value))
    emitted: list[ExtractedString] = []
    emitted_bytes = 0
    truncated = len(candidates) > max_strings
    for candidate in candidates[:max_strings]:
        encoded_size = len(candidate.value.encode("utf-8"))
        if emitted_bytes + encoded_size > max_bytes:
            truncated = True
            break
        emitted.append(candidate)
        emitted_bytes += encoded_size
        truncated = truncated or candidate.value_truncated

    return StringResult(
        entries=emitted,
        truncated=truncated,
        emitted_bytes=emitted_bytes,
        total_found=len(candidates),
    )


def extract_strings_file(
    path: Path,
    *,
    min_length: int = 4,
    max_strings: int = 10_000,
    max_bytes: int = 2_000_000,
    max_string_bytes: int = 4_096,
    deadline: float | None = None,
    chunk_size: int = 1024 * 1024,
) -> StringResult:
    """Extract strings from a file without loading the complete input into memory."""

    return _extract(
        lambda: path.open("rb"),
        min_length=min_length,
        max_strings=max_strings,
        max_bytes=max_bytes,
        max_string_bytes=max_string_bytes,
        deadline=deadline,
        chunk_size=chunk_size,
    )


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    max_strings: int = 10_000,
    max_bytes: int = 2_000_000,
    max_string_bytes: int = 4_096,
    deadline: float | None = None,
) -> StringResult:
    """Extract strings from supplied bytes (primarily for tests and API callers)."""

    return _extract(
        lambda: io.BytesIO(data),
        min_length=min_length,
        max_strings=max_strings,
        max_bytes=max_bytes,
        max_string_bytes=max_string_bytes,
        deadline=deadline,
        chunk_size=1024 * 1024,
    )
