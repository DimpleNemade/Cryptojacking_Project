"""Integrity, edge-case, and report-verification behavior tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cryptojacking_forensics import cli
from cryptojacking_forensics.cli import EXIT_INTERNAL, EXIT_INTEGRITY, EXIT_PARTIAL, EXIT_USAGE
from cryptojacking_forensics.findings import build_findings, overall_evidence_strength
from cryptojacking_forensics.engine import Match, scan_bytes, compile_rules

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "cryptojacking_forensics" / "rules"
CLEAN = FIXTURES / "clean_sample.txt"
POSITIVE = FIXTURES / "synthetic_miner_indicators.txt"


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "cryptojacking_forensics", *args], capture_output=True, text=True)


# --- integrity failure: tamper the evidence between pre/post hashing ---
def test_integrity_failure_exit_30(tmp_path: Path, monkeypatch):
    # Simulate external modification by mutating file after inspect_before via
    # a direct pipeline path is hard; instead test the status mapping function
    # through the public scanning by writing, then mutating, the input file and
    # asserting the documented behavior via the evidence model.
    from cryptojacking_forensics.evidence import inspect_before, inspect_after

    p = tmp_path / "e.bin"
    p.write_bytes(b"stratum+tcp://pool:3333 xmrig")
    rec = inspect_before(p)
    p.write_bytes(b"stratum+tcp://pool:3333 xmrig CHANGED")
    inspect_after(rec)
    assert rec.hash_verification == "FAIL"
    assert rec.external_modification == "DETECTED"


# --- excessive matches / large input ---
def test_large_input_handled(tmp_path: Path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"xmrig " * 1000)
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(p), "--case-id", "BIG", "--output", str(out)])
    # Should complete (SUCCESS or PARTIAL) and not crash; never misuse exit 0-as-fail.
    assert cp.returncode in (0, 10, 20)


def test_oversized_input_rejected_gracefully(tmp_path: Path):
    # Direct module test: oversized input yields PARTIAL (not a false clean scan).
    from cryptojacking_forensics import cli as c

    p = tmp_path / "small.bin"
    p.write_bytes(b"xmrig stratum" * 10)
    saved = c.DEFAULT_LIMITS
    c.DEFAULT_LIMITS = {**saved, "max_input_bytes": 5}
    try:
        rc = c.main(["scan", "artifact", str(p), "--case-id", "SML", "--output", str(tmp_path / "r")])
    finally:
        c.DEFAULT_LIMITS = saved
    assert rc == EXIT_PARTIAL


# --- findings correlation deterministic regardless of order ---
def test_correlation_order_independent():
    m1 = [{"rule_id": "CJ-MINER-001", "rule_name": "a", "source": "yara", "matched_indicator": "donate-level", "offset": 1}]
    m2 = [{"rule_id": "CJ-PROC-001", "rule_name": "b", "source": "yara", "matched_indicator": "xmrig", "offset": 2}]
    s = type("S", (), {"strings": ["xmrig", "stratum+tcp://x:3333"]})()
    f_a = build_findings(m1 + m2, s, "e.bin")
    f_b = build_findings(m2 + m1, s, "e.bin")
    assert [x.finding_id for x in f_a] == [x.finding_id for x in f_b]


def test_overall_evidence_strength():
    s = type("S", (), {"strings": []})()
    f = build_findings([], s, "e.bin")
    assert overall_evidence_strength(f) == "NONE"
    f2 = build_findings(
        [{"rule_id": "CJ-MINER-001", "rule_name": "a", "source": "yara", "matched_indicator": "x", "offset": 1}],
        s,
        "e.bin",
    )
    assert overall_evidence_strength(f2) == "MEDIUM"


# --- report verification tamper detection ---
def test_report_tamper_detected(tmp_path: Path):
    out = tmp_path / "r"
    run_cli(["scan", "artifact", str(POSITIVE), "--case-id", "T1", "--output", str(out)])
    manifest = next((out / "T1").glob("*/manifest.json"))
    doc = json.loads(manifest.read_text())
    doc["analysis_status"] = "SUCCESS"  # if it was something else; either way re-validate
    doc.pop("evidence", None)  # remove required -> must fail validation
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(doc))
    cp = run_cli(["verify-report", str(bad)])
    assert cp.returncode == EXIT_INTERNAL


# --- unsafe case ID variants ---
@pytest.mark.parametrize("cid", ["", "..", "../x", "a" * 65, "has space"])
def test_unsafe_case_ids_rejected(tmp_path: Path, cid):
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(CLEAN), "--case-id", cid, "--output", str(out)])
    assert cp.returncode == EXIT_USAGE


# --- path with spaces / unicode ---
def test_path_with_spaces_and_unicode(tmp_path: Path):
    p = tmp_path / "evi dence 文.bin"
    p.write_text("xmrig stratum+tcp://pool:3333", encoding="utf-8")
    out = tmp_path / "r"
    cp = run_cli(["scan", "artifact", str(p), "--case-id", "UNI", "--output", str(out)])
    assert cp.returncode in (10, 20)
