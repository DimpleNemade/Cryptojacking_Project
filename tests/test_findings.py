import re
from pathlib import Path

from cryptojacking_forensics.findings import RULE_SEVERITY, build_findings

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_corrected_yara_rule_name_detection() -> None:
    output = (
        "generic_stratum_miner /evidence/sample.bin\n"
        "0x20:$s1: stratum+tcp\n"
    )
    findings = build_findings(
        [("miner_rules.yar", output)], "", "/evidence/sample.bin"
    )
    yara_findings = [finding for finding in findings if finding.rule_name]
    assert [finding.rule_name for finding in yara_findings] == [
        "generic_stratum_miner"
    ]
    assert yara_findings[0].offset == 0x20


def test_stratum_spelling_logic() -> None:
    findings = build_findings([], "STRATUM+TCP://example.invalid:3333", "sample")
    assert any(finding.matched_indicator == "stratum+tcp" for finding in findings)
    typo_findings = build_findings([], "startum+tcp://example.invalid", "sample")
    assert not typo_findings


def test_scoring_rule_names_exist_in_yara_files() -> None:
    rule_names: set[str] = set()
    for rule_file in (PROJECT_ROOT / "YARA_Rules").glob("*.yar"):
        rule_names.update(
            re.findall(r"^rule\s+([A-Za-z_][A-Za-z0-9_]*)", rule_file.read_text(), re.M)
        )
    assert set(RULE_SEVERITY) <= rule_names
    assert "generic_startum_miner" not in rule_names


def test_wallet_format_match_is_candidate_and_low_confidence() -> None:
    wallet_candidate = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    findings = build_findings([], wallet_candidate, "sample")
    wallet_findings = [
        finding for finding in findings if finding.finding_type == "WALLET_CANDIDATE"
    ]
    assert len(wallet_findings) == 1
    assert wallet_findings[0].matched_indicator == wallet_candidate
    assert wallet_findings[0].severity == "LOW"
    assert wallet_findings[0].confidence == "LOW"
    assert "not validated" in wallet_findings[0].explanation


def test_corroborating_findings_are_not_independent() -> None:
    output = "xmrig_indicators sample.bin\n0x20:$name1: xmrig\n"
    findings = build_findings(
        [("miner_rules.yar", output)], "xmrig", "sample.bin"
    )
    assert len(findings) == 2
    assert {finding.finding_group_id for finding in findings} == {"G-0001"}
    assert sum(finding.independent_indicator for finding in findings) == 1
    primary = next(finding for finding in findings if finding.independent_indicator)
    corroborating = next(
        finding for finding in findings if not finding.independent_indicator
    )
    assert corroborating.corroborates_finding_id == primary.finding_id
    assert primary.severity == "HIGH"
    assert corroborating.severity == "MEDIUM"
