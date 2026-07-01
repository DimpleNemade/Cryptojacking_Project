from pathlib import Path

import pytest

from cryptojacking_forensics.case import (
    create_case_run,
    ensure_contained,
    validate_case_id,
)
from cryptojacking_forensics.errors import InvalidCaseID, UnsafeOutputPath


@pytest.mark.parametrize("case_id", ["CASE001", "case-2026.01", "A_b"])
def test_valid_case_id_accepted(case_id: str) -> None:
    assert validate_case_id(case_id) == case_id


@pytest.mark.parametrize(
    "case_id",
    ["", "../escape", "..", "/tmp/escape", "case;rm", "case id", "x" * 65],
)
def test_invalid_case_id_rejected(case_id: str) -> None:
    with pytest.raises(InvalidCaseID):
        validate_case_id(case_id)


def test_output_path_containment(tmp_path: Path) -> None:
    reports = tmp_path / "Reports"
    reports.mkdir()
    inside = reports / "case" / "run"
    assert ensure_contained(reports, inside) == inside.resolve()
    with pytest.raises(UnsafeOutputPath):
        ensure_contained(reports, reports / ".." / "outside")


def test_preexisting_case_symlink_cannot_escape_reports(tmp_path: Path) -> None:
    reports = tmp_path / "Reports"
    outside = tmp_path / "outside"
    reports.mkdir()
    outside.mkdir()
    (reports / "CASE001").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeOutputPath):
        create_case_run(reports, "CASE001")


def test_each_case_run_has_a_unique_directory(tmp_path: Path) -> None:
    first = create_case_run(tmp_path / "Reports", "CASE001")
    second = create_case_run(tmp_path / "Reports", "CASE001")
    assert first.run_dir != second.run_dir
    assert first.run_dir.exists()
    assert second.run_dir.exists()

