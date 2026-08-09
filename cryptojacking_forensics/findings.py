"""Structured findings with evidence strength and corroboration.

Replaces the prior "risk severity" model. We never present the capped indicator
count as a probability or risk score. Each finding carries an evidence-strength
(WEAK/MEDIUM/STRONG) derived from rule confidence, and an analytic confidence.
Correlation is deterministic and independent of which match is seen first.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from typing import Any

LIMITATION = (
    "This tool performs triage indicator scanning over supplied artifacts. It does "
    "not prove compromise by itself. Findings require analyst validation."
)

# Rule confidence comes from rule metadata; map to evidence strength.
RULE_EVIDENCE_STRENGTH = {
    "CJ-MINER-001": "MEDIUM",
    "CJ-NET-001": "MEDIUM",
    "CJ-PROC-001": "WEAK",
}

WALLET_PATTERNS = (
    ("BITCOIN_STYLE", re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![1-9A-HJ-NP-Za-km-z])")),
    ("MONERO_STYLE", re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![1-9A-HJ-NP-Za-km-z])")),
)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    finding_type: str
    source: str
    rule_id: str | None
    rule_name: str | None
    matched_indicator: str | None
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


def build_findings(
    scan_matches: list[dict[str, Any]],
    string_result: Any,
    evidence_reference: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_rules: dict[str, int] = {}

    for m in scan_matches:
        rid = str(m.get("rule_id") or m.get("rule_name") or "UNKNOWN")
        strength = RULE_EVIDENCE_STRENGTH.get(rid, "WEAK")
        idx = len(findings) + 1
        if rid in seen_rules:
            # Corroboration: record against the primary finding for this rule.
            primary = findings[seen_rules[rid]]
            findings.append(
                Finding(
                    finding_id=f"F-{idx:04d}",
                    finding_type="YARA_RULE_MATCH",
                    source=str(m.get("source", "yara")),
                    rule_id=rid,
                    rule_name=str(m.get("rule_name")),
                    matched_indicator=m.get("matched_indicator"),
                    offset=m.get("offset"),
                    evidence_strength=strength,
                    confidence="MEDIUM" if strength != "WEAK" else "LOW",
                    explanation=f"YARA rule '{rid}' matched the evidence (corroborating occurrence).",
                    evidence_reference=evidence_reference,
                    corroborates_finding_id=primary.finding_id,
                    independent_indicator=False,
                    correlation_note=f"Corroborates {primary.finding_id} by the same rule.",
                )
            )
            continue
        seen_rules[rid] = len(findings)
        findings.append(
            Finding(
                finding_id=f"F-{idx:04d}",
                finding_type="YARA_RULE_MATCH",
                source=str(m.get("source", "yara")),
                rule_id=rid,
                rule_name=str(m.get("rule_name")),
                matched_indicator=m.get("matched_indicator"),
                offset=m.get("offset"),
                evidence_strength=strength,
                confidence="MEDIUM" if strength != "WEAK" else "LOW",
                explanation=f"YARA rule '{rid}' matched the evidence.",
                evidence_reference=evidence_reference,
            )
        )

    lower = (string_result.strings if string_result else [])
    text = "\n".join(lower).lower()
    string_indicators = (
        ("stratum+tcp://", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("stratum+ssl://", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("xmrig", "MINER_NAME_INDICATOR", "WEAK"),
    )
    for indicator, ftype, strength in string_indicators:
        if indicator in text:
            idx = len(findings) + 1
            findings.append(
                Finding(
                    finding_id=f"F-{idx:04d}",
                    finding_type=ftype,
                    source="strings",
                    rule_id=None,
                    rule_name=None,
                    matched_indicator=indicator,
                    offset=None,
                    evidence_strength=strength,
                    confidence="LOW",
                    explanation=f"Extracted strings contain the indicator '{indicator}'.",
                    evidence_reference=evidence_reference,
                )
            )

    seen_wallet: set[str] = set()
    for _style, pattern in WALLET_PATTERNS:
        for match in pattern.finditer("\n".join(lower)):
            cand = match.group(0)
            if cand in seen_wallet:
                continue
            seen_wallet.add(cand)
            idx = len(findings) + 1
            findings.append(
                Finding(
                    finding_id=f"F-{idx:04d}",
                    finding_type="WALLET_CANDIDATE",
                    source="strings",
                    rule_id=None,
                    rule_name=None,
                    matched_indicator=cand,
                    offset=None,
                    evidence_strength="WEAK",
                    confidence="LOW",
                    explanation=(
                        "Extracted strings contain a wallet-format candidate; checksum, "
                        "ownership, and activity were not validated."
                    ),
                    evidence_reference=evidence_reference,
                )
            )

    # Deterministic correlation keys (order-independent).
    return correlate(findings)


def _correlation_key(f: Finding) -> str:
    ind = (f.matched_indicator or "").strip().lower()
    if f.finding_type == "WALLET_CANDIDATE" and ind:
        return f"wallet:{ind}"
    if ind == "xmrig":
        return "miner-name:xmrig"
    if ind.startswith("stratum"):
        return "protocol:stratum"
    if ind:
        return f"indicator:{ind}"
    if f.rule_id:
        return f"rule:{f.rule_id}"
    return f"finding:{f.finding_id}"


def correlate(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, tuple[str, str]] = {}
    out: list[Finding] = []
    for f in findings:
        key = _correlation_key(f)
        existing = groups.get(key)
        if existing is None:
            gid = f"G-{len(groups) + 1:04d}"
            groups[key] = (gid, f.finding_id)
            out.append(replace(f, finding_group_id=gid, independent_indicator=True,
                               correlation_note="Primary record for this correlated indicator group."))
            continue
        gid, primary = existing
        out.append(replace(f, finding_group_id=gid, corroborates_finding_id=primary,
                           independent_indicator=False,
                           correlation_note=f"Corroborates {primary} through another source."))
    return out


def evidence_strength_rank(strength: str) -> int:
    return {"NONE": 0, "WEAK": 1, "MEDIUM": 2, "STRONG": 3}.get(strength, 0)


def overall_evidence_strength(findings: list[Finding]) -> str:
    if not findings:
        return "NONE"
    best = max((f.evidence_strength for f in findings), key=evidence_strength_rank)
    return best
