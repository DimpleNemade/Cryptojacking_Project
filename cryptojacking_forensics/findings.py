"""Deterministic, privacy-aware triage findings and correlation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, replace
from typing import Any

LIMITATION = (
    "This tool performs indicator triage over supplied artifacts. It does not prove "
    "compromise; every finding requires analyst validation."
)

RULE_EVIDENCE_STRENGTH = {
    "CJ-MINER-001": "MEDIUM",
    "CJ-NET-001": "MEDIUM",
    "CJ-PROC-001": "WEAK",
}

WALLET_PATTERNS = (
    (
        "BITCOIN_STYLE",
        re.compile(
            r"(?<![1-9A-HJ-NP-Za-km-z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
            r"(?![1-9A-HJ-NP-Za-km-z])"
        ),
    ),
    (
        "MONERO_STYLE",
        re.compile(
            r"(?<![1-9A-HJ-NP-Za-km-z])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
            r"(?![1-9A-HJ-NP-Za-km-z])"
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    finding_type: str
    source: str
    rule_id: str | None
    rule_name: str | None
    matched_indicator: str | None
    matched_indicator_sha256: str | None
    offset: int | None
    evidence_strength: str
    confidence: str
    explanation: str
    evidence_reference: str
    finding_group_id: str = ""
    corroborates_finding_id: str | None = None
    independent_indicator: bool = True
    correlation_note: str = ""
    limitations: str = LIMITATION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _indicator_hash(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _string_entries(string_result: Any) -> list[Any]:
    entries = getattr(string_result, "entries", None)
    if entries is not None:
        return list(entries)
    return [
        type("Entry", (), {"value": value, "offset": None, "encoding": "unknown"})()
        for value in getattr(string_result, "strings", [])
    ]


def _entry_offset(entry: Any, character_offset: int) -> int | None:
    base = getattr(entry, "offset", None)
    if base is None:
        return None
    multiplier = 2 if getattr(entry, "encoding", "") == "utf-16le" else 1
    return int(base) + character_offset * multiplier


def build_findings(
    scan_matches: list[dict[str, Any]],
    string_result: Any,
    evidence_reference: str,
    *,
    include_raw_indicators: bool = False,
) -> list[Finding]:
    """Build stable findings; raw matched values are opt-in only."""

    provisional: list[Finding] = []
    for match in scan_matches:
        rule_id = str(match.get("rule_id") or match.get("rule_name") or "UNKNOWN")
        strength = RULE_EVIDENCE_STRENGTH.get(rule_id, "WEAK")
        indicator = match.get("matched_indicator")
        indicator = str(indicator) if indicator is not None else None
        provisional.append(
            Finding(
                finding_id="",
                finding_type="YARA_RULE_MATCH",
                source=str(match.get("source", "yara")),
                rule_id=rule_id,
                rule_name=str(match.get("rule_name") or ""),
                matched_indicator=indicator,
                matched_indicator_sha256=_indicator_hash(indicator),
                offset=match.get("offset"),
                evidence_strength=strength,
                confidence="MEDIUM" if strength != "WEAK" else "LOW",
                explanation=f"YARA rule '{rule_id}' matched the supplied artifact.",
                evidence_reference=evidence_reference,
            )
        )

    entries = _string_entries(string_result)
    indicators = (
        ("stratum+tcp://", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("stratum+ssl://", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("xmrig", "MINER_NAME_INDICATOR", "WEAK"),
    )
    for indicator, finding_type, strength in indicators:
        first: tuple[Any, int] | None = None
        for entry in entries:
            position = entry.value.lower().find(indicator)
            if position >= 0:
                first = (entry, position)
                break
        if first is None:
            continue
        entry, position = first
        provisional.append(
            Finding(
                finding_id="",
                finding_type=finding_type,
                source="strings",
                rule_id=None,
                rule_name=None,
                matched_indicator=indicator,
                matched_indicator_sha256=_indicator_hash(indicator),
                offset=_entry_offset(entry, position),
                evidence_strength=strength,
                confidence="LOW",
                explanation="A bounded extracted string contained this indicator type.",
                evidence_reference=evidence_reference,
            )
        )

    seen_wallets: set[str] = set()
    for entry in entries:
        for _style, pattern in WALLET_PATTERNS:
            for wallet_match in pattern.finditer(entry.value):
                candidate = wallet_match.group(0)
                if candidate in seen_wallets:
                    continue
                seen_wallets.add(candidate)
                provisional.append(
                    Finding(
                        finding_id="",
                        finding_type="WALLET_CANDIDATE",
                        source="strings",
                        rule_id=None,
                        rule_name=None,
                        matched_indicator=candidate,
                        matched_indicator_sha256=_indicator_hash(candidate),
                        offset=_entry_offset(entry, wallet_match.start()),
                        evidence_strength="WEAK",
                        confidence="LOW",
                        explanation=(
                            "An extracted string matched a wallet-shaped pattern; checksum, "
                            "ownership, and activity were not validated."
                        ),
                        evidence_reference=evidence_reference,
                    )
                )

    provisional.sort(
        key=lambda item: (
            item.offset is None,
            item.offset if item.offset is not None else 0,
            item.finding_type,
            item.source,
            item.rule_id or "",
            item.matched_indicator_sha256 or "",
        )
    )
    identified = [
        replace(item, finding_id=f"F-{index:04d}") for index, item in enumerate(provisional, 1)
    ]
    correlated = correlate(identified)
    if include_raw_indicators:
        return correlated
    return [replace(item, matched_indicator=None) for item in correlated]


def _correlation_key(finding: Finding) -> str:
    indicator = (finding.matched_indicator or "").strip().lower()
    if finding.finding_type == "WALLET_CANDIDATE" and finding.matched_indicator_sha256:
        return f"wallet:{finding.matched_indicator_sha256}"
    if indicator == "xmrig":
        return "miner-name:xmrig"
    if indicator.startswith("stratum"):
        return "protocol:stratum"
    if finding.matched_indicator_sha256:
        return f"indicator:{finding.matched_indicator_sha256}"
    if finding.rule_id:
        return f"rule:{finding.rule_id}"
    return f"finding:{finding.finding_id}"


def correlate(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, tuple[str, str]] = {}
    output: list[Finding] = []
    for finding in findings:
        key = _correlation_key(finding)
        existing = groups.get(key)
        if existing is None:
            group_id = f"G-{len(groups) + 1:04d}"
            groups[key] = (group_id, finding.finding_id)
            output.append(
                replace(
                    finding,
                    finding_group_id=group_id,
                    independent_indicator=True,
                    correlation_note="Primary record for this correlated indicator group.",
                )
            )
            continue
        group_id, primary = existing
        output.append(
            replace(
                finding,
                finding_group_id=group_id,
                corroborates_finding_id=primary,
                independent_indicator=False,
                correlation_note=f"Corroborates {primary} through another observation.",
            )
        )
    return output


def evidence_strength_rank(strength: str) -> int:
    return {"NONE": 0, "WEAK": 1, "MEDIUM": 2, "STRONG": 3}.get(strength, 0)


def overall_evidence_strength(findings: list[Finding]) -> str:
    if not findings:
        return "NONE"
    return max((item.evidence_strength for item in findings), key=evidence_strength_rank)
