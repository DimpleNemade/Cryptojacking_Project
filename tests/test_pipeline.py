from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptojacking_forensics import cli
from cryptojacking_forensics.commands import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def result(command: list[str], stdout: str = "", return_code: int = 0) -> CommandResult:
    return CommandResult(
        command=command,
        return_code=return_code,
        stdout=stdout,
        stderr="synthetic failure" if return_code else "",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_seconds=1.0,
    )


@pytest.fixture
def rules_root(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "miner_rules.yar").write_text("rule xmrig_indicators { condition: false }\n")
    return rules


def mock_tools(monkeypatch: pytest.MonkeyPatch, *, infected: bool = False) -> None:
    def fake_yara(evidence: Path, rules: list[Path], timeout: float):
        output = ""
        if infected:
            output = "xmrig_indicators synthetic.bin\n0x0:$name1: xmrig\n"
        return [(rule, result(["yara", str(rule), str(evidence)], output)) for rule in rules]

    def fake_strings(evidence: Path, timeout: float):
        output = "xmrig\nstratum+tcp://example.invalid:3333\n" if infected else "ordinary text\n"
        return result(["strings", str(evidence)], output)

    monkeypatch.setattr(cli, "scan_with_yara", fake_yara)
    monkeypatch.setattr(cli, "extract_strings", fake_strings)
    monkeypatch.setattr(
        cli,
        "_tool_version",
        lambda command, timeout_seconds=5: ("test-version", result(command)),
    )


@pytest.mark.parametrize(
    ("fixture_name", "infected", "expected_count"),
    [("clean_sample.txt", False, 0), ("synthetic_miner_indicators.txt", True, 3)],
)
def test_pipeline_generates_required_artifacts(
    tmp_path: Path,
    rules_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_name: str,
    infected: bool,
    expected_count: int,
) -> None:
    mock_tools(monkeypatch, infected=infected)
    run_dir = cli.run_pipeline(
        FIXTURES / fixture_name,
        "CASE001",
        reports_root=tmp_path / "Reports",
        rules_root=rules_root,
    )

    for name in (
        "summary.txt",
        "summary.json",
        "findings.json",
        "manifest.json",
        "yara.txt",
        "strings.txt",
    ):
        assert (run_dir / name).is_file()

    findings = json.loads((run_dir / "findings.json").read_text())
    summary = json.loads((run_dir / "summary.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert len(findings) == expected_count
    assert summary["finding_count"] == expected_count
    expected_independent = 2 if infected else 0
    assert summary["independent_indicator_count"] == expected_independent
    assert summary["unvalidated_triage_score"] == expected_independent
    assert sum(item["independent_indicator"] for item in findings) == expected_independent
    assert summary["analysis_status"] == "SUCCESS"
    assert manifest["analysis_status"] == summary["analysis_status"]
    assert manifest["hash_verification"] == "PASS"
    assert manifest["input_sha256_before"] == manifest["input_sha256_after"]
    assert manifest["input_file_display"] == fixture_name
    assert manifest["path_disclosure_notice"]
    assert manifest["output_files"]
    assert all(item["sha256"] for item in manifest["output_files"])
    assert all(item["display_path"] for item in manifest["output_files"])


def test_failed_subprocess_is_not_reported_clean(
    tmp_path: Path,
    rules_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "scan_with_yara",
        lambda evidence, rules, timeout: [
            (rule, result(["yara", str(rule), str(evidence)], return_code=2))
            for rule in rules
        ],
    )
    monkeypatch.setattr(
        cli,
        "extract_strings",
        lambda evidence, timeout: result(["strings", str(evidence)], return_code=1),
    )
    monkeypatch.setattr(
        cli,
        "_tool_version",
        lambda command, timeout_seconds=5: ("test-version", result(command)),
    )

    run_dir = cli.run_pipeline(
        FIXTURES / "clean_sample.txt",
        "FAILED_CASE",
        reports_root=tmp_path / "Reports",
        rules_root=rules_root,
    )
    summary = json.loads((run_dir / "summary.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert summary["analysis_status"] == "FAILED"
    assert summary["risk_severity"] == "UNDETERMINED"
    assert "must not be interpreted as clean" in summary["explanation"]
    assert manifest["errors"]
    assert manifest["command_return_codes"][:2] == [2, 1]


def test_one_failed_analysis_component_is_partial(
    tmp_path: Path,
    rules_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "scan_with_yara",
        lambda evidence, rules, timeout: [
            (rule, result(["yara", str(rule), str(evidence)], return_code=2))
            for rule in rules
        ],
    )
    monkeypatch.setattr(
        cli,
        "extract_strings",
        lambda evidence, timeout: result(["strings", str(evidence)], "ordinary text"),
    )
    monkeypatch.setattr(
        cli,
        "_tool_version",
        lambda command, timeout_seconds=5: ("test-version", result(command)),
    )
    run_dir = cli.run_pipeline(
        FIXTURES / "clean_sample.txt",
        "PARTIAL_CASE",
        reports_root=tmp_path / "Reports",
        rules_root=rules_root,
    )
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["analysis_status"] == "PARTIAL"
    assert summary["risk_severity"] == "UNDETERMINED"


def test_hash_mismatch_marks_integrity_failure(
    tmp_path: Path,
    rules_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "mutable_evidence.bin"
    evidence.write_bytes(b"before")
    monkeypatch.setattr(
        cli,
        "scan_with_yara",
        lambda evidence_path, rules, timeout: [
            (rule, result(["yara", str(rule), str(evidence_path)])) for rule in rules
        ],
    )

    def mutate_during_strings(evidence_path: Path, timeout: float) -> CommandResult:
        evidence_path.write_bytes(b"after")
        return result(["strings", str(evidence_path)], "ordinary text")

    monkeypatch.setattr(cli, "extract_strings", mutate_during_strings)
    monkeypatch.setattr(
        cli,
        "_tool_version",
        lambda command, timeout_seconds=5: ("test-version", result(command)),
    )
    run_dir = cli.run_pipeline(
        evidence,
        "INTEGRITY_CASE",
        reports_root=tmp_path / "Reports",
        rules_root=rules_root,
    )
    summary = json.loads((run_dir / "summary.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert summary["analysis_status"] == "INTEGRITY_FAILURE"
    assert summary["hash_verification"] == "FAIL"
    assert summary["risk_severity"] == "UNDETERMINED"
    assert manifest["input_sha256_before"] != manifest["input_sha256_after"]
