"""CLI contract, command parsing, and stable exit-code tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cryptojacking_forensics import cli
from cryptojacking_forensics.cli import EXIT_INTERNAL, EXIT_OK_FINDINGS, EXIT_OK_NO_FINDINGS, EXIT_PARTIAL, EXIT_USAGE

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = FIXTURES / "clean_sample.txt"
POSITIVE = FIXTURES / "synthetic_miner_indicators.txt"


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "cryptojacking_forensics", *args],
        capture_output=True,
        text=True,
    )


# --- exit-code contract ---
def test_scan_clean_exit_0(tmp_path: Path):
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(CLEAN), "--case-id", "C1", "--output", str(out)])
    assert cp.returncode == EXIT_OK_NO_FINDINGS, cp.stderr


def test_scan_positive_exit_10(tmp_path: Path):
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C2", "--output", str(out)])
    assert cp.returncode == EXIT_OK_FINDINGS, cp.stderr


def test_scan_bad_case_id_exit_64(tmp_path: Path):
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(CLEAN), "--case-id", "bad id", "--output", str(out)])
    assert cp.returncode == EXIT_USAGE, cp.stderr


def test_scan_missing_file_exit_64(tmp_path: Path):
    cp = run_cli(["scan", "artifact", str(tmp_path / "nope.bin"), "--case-id", "C3", "--output", str(tmp_path / "r")])
    assert cp.returncode == EXIT_USAGE, cp.stderr


def test_version_exit_0():
    cp = run_cli(["--version"])
    assert cp.returncode == 0
    assert "0.1.0a1" in cp.stdout


def test_help_top_level():
    cp = run_cli(["--help"])
    assert cp.returncode == 0
    for sub in ("scan", "doctor", "rules", "verify-report", "version"):
        assert sub in cp.stdout


# --- doctor / rules / verify subcommands ---
def test_doctor_json():
    cp = run_cli(["doctor", "--format", "json"])
    assert cp.returncode == 0
    data = json.loads(cp.stdout)
    assert data["engine"]["name"] == "yara-python"


def test_rules_check_ok():
    cp = run_cli(["rules", "check"])
    assert cp.returncode == 0
    assert "OK" in cp.stderr


def test_verify_summary_valid(tmp_path: Path):
    out = tmp_path / "r"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C4", "--output", str(out)])
    summary = next((out / "C4").glob("*/summary.json"))
    cp = run_cli(["verify-report", str(summary)])
    assert cp.returncode == 0, cp.stderr
    assert "VALID" in cp.stderr


def test_verify_missing_file_exit_64(tmp_path: Path):
    cp = run_cli(["verify-report", str(tmp_path / "missing.json")])
    assert cp.returncode == EXIT_USAGE


def test_verify_tampered_report_exit_70(tmp_path: Path):
    out = tmp_path / "r"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C5", "--output", str(out)])
    summary = next((out / "C5").glob("*/summary.json"))
    text = summary.read_text()
    # Break schema: remove required field.
    broken = text.replace('"analysis_status"', '"analysis_status_X"')
    bad = tmp_path / "bad.json"
    bad.write_text(broken)
    cp = run_cli(["verify-report", str(bad)])
    assert cp.returncode == EXIT_INTERNAL, cp.stderr


# --- stdout/stderr discipline ---
def test_machine_output_on_stdout_only_when_json(tmp_path: Path):
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C6", "--output", str(out), "--format", "json"])
    # JSON payload on stdout
    payload = json.loads(cp.stdout)
    assert "summary" in payload
    # diagnostics on stderr only
    assert "Analysis complete" in cp.stderr


def test_raw_optin_writes_strings(tmp_path: Path):
    out = tmp_path / "r"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C7", "--output", str(out), "--raw"])
    strings_file = next((out / "C7").glob("*/strings.txt"))
    assert strings_file.exists()
    assert strings_file.read_text()


# --- privacy default: no absolute path in summary by default ---
def test_privacy_default_no_abspath(tmp_path: Path):
    out = tmp_path / "r"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "C8", "--output", str(out)])
    summary = next((out / "C8").glob("*/summary.json"))
    manifest = next((out / "C8").glob("*/manifest.json"))
    mtxt = manifest.read_text()
    # input_file should be null by default (only display name kept)
    assert '"input_file": null' in mtxt
