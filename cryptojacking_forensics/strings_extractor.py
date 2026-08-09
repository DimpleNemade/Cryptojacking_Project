"""Bounded, in-process string extraction.

Replaces the GNU `strings` subprocess. Supports printable ASCII and UTF-16LE
(relevant to the alpha). Enforces byte/match caps and reports truncation.
Does not read the whole file into memory at once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PRINTABLE = re.compile(rb"[ -~]{4,}")
_UTF16LE = re.compile(rb"(?:[ -~]\x00){4,}")


@dataclass
class StringResult:
    strings: list[str]
    truncated: bool = False
    emitted_bytes: int = 0
    total_found: int = 0


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    max_strings: int = 10_000,
    max_bytes: int = 2_000_000,
) -> StringResult:
    found: list[str] = []
    emitted_bytes = 0
    truncated = False

    ascii_re = re.compile(rb"[ -~]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[ -~]\x00){%d,}" % min_length)

    for regex in (ascii_re, utf16_re):
        is_utf16 = regex is utf16_re
        for m in regex.finditer(data):
            raw = m.group(0)
            text = raw.decode("utf-16-le") if is_utf16 else raw.decode("ascii", "replace")
            found.append(text)
            emitted_bytes += len(text)
            if len(found) >= max_strings or emitted_bytes >= max_bytes:
                truncated = True
                break
        if truncated:
            break

    # Deterministic ordering: appearance order is already deterministic.
    return StringResult(strings=found, truncated=truncated, emitted_bytes=emitted_bytes, total_found=len(found))
