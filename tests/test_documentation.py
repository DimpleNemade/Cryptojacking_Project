from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("relative_path", ["docs/VALIDATION.md", "docs/LIMITATIONS.md"])
def test_required_document_exists(relative_path: str) -> None:
    path = PROJECT_ROOT / relative_path
    assert path.is_file()
    assert path.read_text(encoding="utf-8").strip()


def test_validation_document_records_required_scope() -> None:
    text = " ".join(
        (PROJECT_ROOT / "docs/VALIDATION.md")
        .read_text(encoding="utf-8")
        .lower()
        .split()
    )
    required_phrases = (
        "purpose",
        "python: 3.12.3",
        "pytest: 8.4.2",
        "yara: 4.5.0",
        "gnu strings",
        "clean fixture",
        "synthetic indicator fixture",
        "known false-positive risks",
        "known false-negative risks",
        "real malware",
        "large real memory dumps",
        "cross-platform operation",
        "legal admissibility validation",
    )
    assert all(phrase in text for phrase in required_phrases)


def test_limitations_document_sets_clear_boundaries() -> None:
    text = " ".join(
        (PROJECT_ROOT / "docs/LIMITATIONS.md")
        .read_text(encoding="utf-8")
        .lower()
        .split()
    )
    required_phrases = (
        "does not prove compromise",
        "acquire evidence",
        "chain of custody",
        "operating-system memory structures",
        "running processes",
        "validated compromise probability",
        "appropriate use",
        "inappropriate use",
        "not court-ready or legally determinative",
    )
    assert all(phrase in text for phrase in required_phrases)


def test_readme_positions_the_project_without_overclaiming() -> None:
    text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8").lower()
    description = (
        "a python-based cryptojacking forensic triage cli that performs yara scanning,\n"
        "string extraction, pre/post sha-256 evidence verification, structured finding\n"
        "generation, run manifest creation, and repeatable case-based reporting."
    )
    assert description in text
    assert "docs/limitations.md" in text
    assert "docs/validation.md" in text
    unsupported_claims = (
        "is production-ready",
        "is enterprise-ready",
        "is court-ready",
        "legally defensible by default",
        "ai-powered",
    )
    assert not any(claim in text for claim in unsupported_claims)
