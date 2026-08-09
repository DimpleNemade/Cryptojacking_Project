"""Shared fixtures and helpers for cryptojacking-forensics tests.

All test data is inert synthetic text. No real samples, miners, or malware.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

CLEAN = FIXTURES / "clean_sample.txt"
POSITIVE = FIXTURES / "synthetic_miner_indicators.txt"


@pytest.fixture
def clean_file() -> Path:
    return CLEAN


@pytest.fixture
def positive_file() -> Path:
    return POSITIVE


@pytest.fixture
def rules_dir() -> Path:
    return Path(__file__).parent.parent / "cryptojacking_forensics" / "rules"


def make_input(tmp_path: Path, content: str, name: str = "evidence.bin") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p
