"""CLI contract and report-bundle integration tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cryptojacking_forensics import cli
from cryptojacking_forensics.cli import (
    EXIT_INTEGRITY,
    EXIT_INTERNAL,
    EXIT_OK_FINDINGS,
    EXIT_OK_NO_FINDINGS,
    EXIT_USAGE,
)

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = FIXTURES / "clean_sample.txt"
POSITIVE = FIXTURES / "synthetic_miner_indicators.txt"


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cryptojacking_forensics", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _run_dir(output: Path, case_id: str) -> Path:
    return next(path for path in (output / case_id).iterdir() if path.is_dir())


def test_scan_clean_exit_0_and_valid_bundle(tmp_path: Path):
    output = tmp_path / "reports"
    result = run_cli(["scan", "artifact", str(CLEAN), "--case-id", "C1", "--output", str(output)])
    assert result.returncode == EXIT_OK_NO_FINDINGS, result.stderr
    run_dir = _run_dir(output, "C1")
    assert {path.name for path in run_dir.iterdir()} == {
        "findings.json",
        "manifest.json",
        "summary.json",
    }
    verified = run_cli(["verify-report", str(run_dir)])
    assert verified.returncode == 0, verified.stderr


def test_scan_positive_exit_10_and_structured_findings(tmp_path: Path):
    output = tmp_path / "reports"
    result = run_cli(
        ["scan", "artifact", str(POSITIVE), "--case-id", "C2", "--output", str(output)]
    )
    assert result.returncode == EXIT_OK_FINDINGS, result.stderr
    document = json.loads((_run_dir(output, "C2") / "findings.json").read_text())
    assert document["schema_version"] == "1.0.0"
    assert document["findings"]
    assert all(item["matched_indicator"] is None for item in document["findings"])
    assert all(item["matched_indicator_sha256"] for item in document["findings"])


def test_bad_inputs_exit_64(tmp_path: Path):
    cases = [
        ["scan", "artifact", str(CLEAN), "--case-id", "bad id"],
        ["scan", "artifact", str(tmp_path / "missing"), "--case-id", "C3"],
        ["scan", "artifact", str(CLEAN), "--case-id", "C3", "--timeout", "0"],
        ["scan", "artifact", str(CLEAN), "--case-id", "C3", "--min-length", "2"],
    ]
    for arguments in cases:
        assert run_cli(arguments).returncode == EXIT_USAGE


def test_help_version_doctor_and_rules():
    version = run_cli(["--version"])
    assert version.returncode == 0
    assert "0.1.0a2" in version.stdout
    help_result = run_cli(["--help"])
    assert help_result.returncode == 0
    for command in ("scan", "doctor", "rules", "verify-report", "version"):
        assert command in help_result.stdout
    doctor = run_cli(["doctor", "--format", "json"])
    assert doctor.returncode == 0, doctor.stderr
    assert json.loads(doctor.stdout)["rule_pack"]["status"] == "OK"
    assert run_cli(["rules", "check"]).returncode == 0


def test_json_stdout_and_quiet(tmp_path: Path):
    output = tmp_path / "reports"
    result = run_cli(
        [
            "scan",
            "artifact",
            str(POSITIVE),
            "--case-id",
            "C4",
            "--output",
            str(output),
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert result.returncode == EXIT_OK_FINDINGS
    payload = json.loads(result.stdout)
    assert payload["report_dir"].startswith("C4/")
    assert "Analysis complete" not in result.stderr


def test_privacy_default_omits_absolute_paths_and_raw_values(tmp_path: Path):
    evidence = tmp_path / "sensitive-name.bin"
    evidence.write_bytes(POSITIVE.read_bytes())
    output = tmp_path / "reports"
    result = run_cli(
        ["scan", "artifact", str(evidence), "--case-id", "SAFE", "--output", str(output)]
    )
    assert result.returncode == EXIT_OK_FINDINGS
    run_dir = _run_dir(output, "SAFE")
    combined = "".join(path.read_text() for path in run_dir.glob("*.json"))
    assert str(tmp_path.resolve()) not in combined
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["evidence"]["input_file"] is None
    assert manifest["outputs"]["report_dir"] is None
    assert all(
        set(record) == {"name", "sha256"} for record in manifest["outputs"]["artifact_hashes"]
    )


def test_raw_opt_in_writes_strings_and_paths(tmp_path: Path):
    output = tmp_path / "reports"
    result = run_cli(
        ["scan", "artifact", str(POSITIVE), "--case-id", "RAW", "--output", str(output), "--raw"]
    )
    assert result.returncode == EXIT_OK_FINDINGS
    run_dir = _run_dir(output, "RAW")
    assert (run_dir / "strings.txt").read_text()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["evidence"]["input_file"] == str(POSITIVE.resolve())
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    assert any(item["matched_indicator"] for item in findings)


def test_bundle_hash_tamper_returns_integrity_exit(tmp_path: Path):
    output = tmp_path / "reports"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "TAMPER", "--output", str(output)])
    run_dir = _run_dir(output, "TAMPER")
    summary = run_dir / "summary.json"
    document = json.loads(summary.read_text())
    document["explanation"] = "tampered but schema-valid"
    summary.write_text(json.dumps(document))
    result = run_cli(["verify-report", str(run_dir / "manifest.json")])
    assert result.returncode == EXIT_INTEGRITY
    assert "hash mismatch" in result.stderr


def test_schema_invalid_report_returns_internal_exit(tmp_path: Path):
    report = tmp_path / "summary.json"
    report.write_text(
        json.dumps(
            {"schema_version": "1.0.0", "analysis_status": "SUCCESS", "evidence_strength": "NONE"}
        )
    )
    result = run_cli(["verify-report", str(report)])
    assert result.returncode == EXIT_INTERNAL
    assert "INVALID" in result.stderr


def test_in_process_command_paths(tmp_path: Path, capsys):
    output = tmp_path / "reports"
    positive = cli.main(
        [
            "scan",
            "artifact",
            str(POSITIVE),
            "--case-id",
            "DIRECT",
            "--output",
            str(output),
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert positive == EXIT_OK_FINDINGS
    assert json.loads(capsys.readouterr().out)["summary"]["analysis_status"] == "SUCCESS"
    run_dir = _run_dir(output, "DIRECT")
    assert cli.main(["verify-report", str(run_dir), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert cli.main(["doctor", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schemas"]["status"] == "OK"
    assert cli.main(["rules", "check", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["rules"]


def test_missing_rules_is_partial_not_clean(tmp_path: Path, capsys):
    output = tmp_path / "reports"
    empty_rules = tmp_path / "empty-rules"
    empty_rules.mkdir()
    result = cli.main(
        [
            "scan",
            "artifact",
            str(CLEAN),
            "--case-id",
            "NORULES",
            "--output",
            str(output),
            "--rules",
            str(empty_rules),
            "--quiet",
        ]
    )
    assert result == cli.EXIT_PARTIAL
    summary = json.loads((_run_dir(output, "NORULES") / "summary.json").read_text())
    assert summary["analysis_status"] == "PARTIAL"
    assert "YARA stage skipped" in " ".join(summary["warnings"])
    capsys.readouterr()
