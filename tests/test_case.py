"""Tests for case-run directory management and CLI exit-code mapping."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptojacking_forensics import cli
from cryptojacking_forensics.case import (
    CaseRun,
    TriageRunCollision,
    create_case_run,
    ensure_contained,
    new_run_id,
    validate_case_id,
)


def test_validate_case_id_accepts_valid():
    assert validate_case_id("CASE-001") == "CASE-001"
    assert validate_case_id("a.b_c-d") == "a.b_c-d"


def test_validate_case_id_rejects_bad():
    for bad in [".", "..", "", "has space", "UPPER?", "../x", "a" * 65, "x/y"]:
        with pytest.raises(Exception):
            validate_case_id(bad)


def test_ensure_contained_allows_inside():
    root = Path("/tmp/reports")
    assert ensure_contained(root, root / "case1" / "run1") == (root / "case1" / "run1").resolve()


def test_ensure_contained_blocks_escape():
    root = Path("/tmp/reports")
    with pytest.raises(Exception):
        ensure_contained(root, Path("/tmp/elsewhere/x"))


def test_create_case_run_unique_dirs(tmp_path: Path):
    r1 = create_case_run(tmp_path, "CASE1")
    r2 = create_case_run(tmp_path, "CASE1")
    assert r1.run_dir != r2.run_dir
    assert r1.run_dir.exists() and r2.run_dir.exists()
    assert r1.case_id == "CASE1"


def test_new_run_id_unique():
    assert new_run_id() != new_run_id()


def test_case_run_frozen():
    cr = CaseRun("C", "R", Path("/tmp/x"), Path("/tmp/x/C/R"))
    with pytest.raises(Exception):
        cr.case_id = "other"  # type: ignore[misc]


# --- exit-code mapping ---
def test_exit_mapping_success_no_findings():
    assert cli._exit_for_status("SUCCESS", "PASS", False) == cli.EXIT_OK_NO_FINDINGS


def test_exit_mapping_success_findings():
    assert cli._exit_for_status("SUCCESS", "PASS", True) == cli.EXIT_OK_FINDINGS


def test_exit_mapping_partial():
    assert cli._exit_for_status("PARTIAL", "PASS", True) == cli.EXIT_PARTIAL
    assert cli._exit_for_status("FAILED", "PASS", True) == cli.EXIT_PARTIAL


def test_exit_mapping_integrity():
    assert cli._exit_for_status("SUCCESS", "FAIL", True) == cli.EXIT_INTEGRITY
    assert cli._exit_for_status("INTEGRITY_FAILURE", "FAIL", True) == cli.EXIT_INTEGRITY
