from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace

from .yara_scanner import parse_yara_matches

LIMITATION = (
    "This tool performs triage indicator scanning. It does not prove compromise by "
    "itself. Findings require analyst validation."
)

RULE_SEVERITY = {
    "xmrig_indicators": ("HIGH", "HIGH"),
    "generic_stratum_miner": ("MEDIUM", "MEDIUM"),
    "crypto_network_indicators": ("MEDIUM", "LOW"),
    "miner_process_names": ("MEDIUM", "MEDIUM"),
}

SAFE_MATCH_VALUE_RULES = {
    "xmrig_indicators",
    "generic_stratum_miner",
    "crypto_network_indicators",
    "miner_process_names",
}

# These patterns identify format candidates only. They do not perform checksum,
# ownership, activity, or cryptocurrency-network validation.
WALLET_CANDIDATE_PATTERNS = (
    (
        "BITCOIN_STYLE",
        re.compile(
            r"(?<![1-9A-HJ-NP-Za-km-z])"
            r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
            r"(?![1-9A-HJ-NP-Za-km-z])"
        ),
    ),
    (
        "MONERO_STYLE",
        re.compile(
            r"(?<![1-9A-HJ-NP-Za-km-z])"
            r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
            r"(?![1-9A-HJ-NP-Za-km-z])"
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    finding_type: str
    source: str
    rule_name: str | None
    matched_indicator: str | None
    offset: int | None
    severity: str
    confidence: str
    explanation: str
    evidence_reference: str
    finding_group_id: str = ""
    corroborates_finding_id: str | None = None
    independent_indicator: bool = True
    correlation_note: str = ""
    limitation: str = LIMITATION

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_findings(
    yara_outputs: list[tuple[str, str]], strings_output: str, evidence_reference: str
) -> list[Finding]:
    candidates: list[dict[str, object]] = []
    for source, output in yara_outputs:
        candidates.extend(parse_yara_matches(output, source))

    # Keep one structured finding per YARA rule. Match detail is retained when YARA
    # emits it, but raw evidence strings are deliberately capped by the parser.
    findings: list[Finding] = []
    seen_rules: set[str] = set()
    for candidate in candidates:
        rule_name = str(candidate["rule_name"])
        safe_indicator = (
            candidate["matched_indicator"]
            if rule_name in SAFE_MATCH_VALUE_RULES
            else None
        )
        if rule_name in seen_rules:
            if safe_indicator is not None:
                for index, existing in enumerate(findings):
                    if existing.rule_name == rule_name and existing.matched_indicator is None:
                        findings[index] = Finding(
                            **{
                                **existing.to_dict(),
                                "matched_indicator": safe_indicator,
                                "offset": candidate["offset"],
                            }
                        )
                        break
            continue
        seen_rules.add(rule_name)
        severity, confidence = RULE_SEVERITY.get(rule_name, ("LOW", "LOW"))
        findings.append(
            Finding(
                finding_id="",
                finding_type="YARA_RULE_MATCH",
                source=str(candidate["source"]),
                rule_name=rule_name,
                matched_indicator=safe_indicator,
                offset=candidate["offset"],
                severity=severity,
                confidence=confidence,
                explanation=f"YARA rule '{rule_name}' matched the evidence.",
                evidence_reference=evidence_reference,
            )
        )

    lower_strings = strings_output.lower()
    string_indicators = (
        ("stratum+tcp", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("stratum+ssl", "MINING_PROTOCOL_INDICATOR", "MEDIUM"),
        ("xmrig", "MINER_NAME_INDICATOR", "MEDIUM"),
    )
    for indicator, finding_type, severity in string_indicators:
        if indicator in lower_strings:
            findings.append(
                Finding(
                    finding_id="",
                    finding_type=finding_type,
                    source="strings",
                    rule_name=None,
                    matched_indicator=indicator,
                    offset=None,
                    severity=severity,
                    confidence="LOW",
                    explanation=f"Extracted strings contain the indicator '{indicator}'.",
                    evidence_reference=evidence_reference,
                )
            )

    seen_wallet_candidates: set[str] = set()
    for wallet_style, pattern in WALLET_CANDIDATE_PATTERNS:
        for match in pattern.finditer(strings_output):
            candidate = match.group(0)
            if candidate in seen_wallet_candidates:
                continue
            seen_wallet_candidates.add(candidate)
            findings.append(
                Finding(
                    finding_id="",
                    finding_type="WALLET_CANDIDATE",
                    source="strings",
                    rule_name=None,
                    matched_indicator=candidate,
                    offset=None,
                    severity="LOW",
                    confidence="LOW",
                    explanation=(
                        f"Extracted strings contain a {wallet_style} wallet-format "
                        "candidate; checksum, ownership, and activity were not validated."
                    ),
                    evidence_reference=evidence_reference,
                )
            )

    with_ids = [
        replace(finding, finding_id=f"F-{index:04d}")
        for index, finding in enumerate(findings, start=1)
    ]
    return correlate_findings(with_ids)


def _correlation_key(finding: Finding) -> str:
    indicator = (finding.matched_indicator or "").strip().lower()
    if indicator == "xmrig":
        return "miner-name:xmrig"
    if indicator.startswith("stratum"):
        return "protocol:stratum"
    if finding.finding_type == "WALLET_CANDIDATE" and indicator:
        return f"wallet-candidate:{indicator}"
    if indicator:
        return f"indicator:{indicator}"
    if finding.rule_name:
        return f"rule:{finding.rule_name}"
    return f"finding:{finding.finding_id}"


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Group corroborating records without treating them as independent indicators."""
    groups: dict[str, tuple[str, str]] = {}
    correlated: list[Finding] = []
    for finding in findings:
        key = _correlation_key(finding)
        existing = groups.get(key)
        if existing is None:
            group_id = f"G-{len(groups) + 1:04d}"
            groups[key] = (group_id, finding.finding_id)
            correlated.append(
                replace(
                    finding,
                    finding_group_id=group_id,
                    corroborates_finding_id=None,
                    independent_indicator=True,
                    correlation_note=(
                        "Primary record for this correlated indicator group."
                    ),
                )
            )
            continue

        group_id, primary_id = existing
        correlated.append(
            replace(
                finding,
                finding_group_id=group_id,
                corroborates_finding_id=primary_id,
                independent_indicator=False,
                correlation_note=(
                    f"Corroborates {primary_id} through another rule or analysis source."
                ),
            )
        )
    return correlated


def overall_severity(findings: list[Finding]) -> str:
    rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max((finding.severity for finding in findings), key=rank.get, default="NONE")
