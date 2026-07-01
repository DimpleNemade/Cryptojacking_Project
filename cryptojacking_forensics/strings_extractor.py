from __future__ import annotations

from pathlib import Path

from .commands import CommandResult, run_command


def extract_strings(evidence_path: Path, timeout_seconds: float) -> CommandResult:
    return run_command(["strings", str(evidence_path)], timeout_seconds)

