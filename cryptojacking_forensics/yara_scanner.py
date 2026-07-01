from __future__ import annotations

import re
from pathlib import Path

from .commands import CommandResult, run_command

RULE_HEADER = re.compile(r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<target>.+)$")
MATCH_LINE = re.compile(r"^0x(?P<offset>[0-9a-fA-F]+):(?P<identifier>\$[^:]+):\s*(?P<value>.*)$")


def scan_with_yara(
    evidence_path: Path, rule_files: list[Path], timeout_seconds: float
) -> list[tuple[Path, CommandResult]]:
    return [
        (
            rule_file,
            run_command(
                ["yara", "-r", "-s", str(rule_file), str(evidence_path)],
                timeout_seconds,
            ),
        )
        for rule_file in rule_files
    ]


def parse_yara_matches(output: str, source: str) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    current_rule: str | None = None
    for line in output.splitlines():
        header = RULE_HEADER.match(line)
        if header and not line.startswith("0x"):
            current_rule = header.group("rule")
            matches.append(
                {
                    "rule_name": current_rule,
                    "source": source,
                    "matched_indicator": None,
                    "offset": None,
                }
            )
            continue
        detail = MATCH_LINE.match(line)
        if detail and current_rule:
            matches.append(
                {
                    "rule_name": current_rule,
                    "source": source,
                    "matched_indicator": detail.group("value")[:200],
                    "offset": int(detail.group("offset"), 16),
                }
            )
    return matches

