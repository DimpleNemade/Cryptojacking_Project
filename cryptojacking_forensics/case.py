from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import InvalidCaseID, UnsafeOutputPath

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_case_id(case_id: str) -> str:
    """Return a safe case ID or raise InvalidCaseID."""
    if not isinstance(case_id, str) or not case_id:
        raise InvalidCaseID("case ID must not be empty")
    if case_id in {".", ".."} or not CASE_ID_PATTERN.fullmatch(case_id):
        raise InvalidCaseID(
            "case ID must be 1-64 characters, begin with a letter or digit, "
            "and contain only letters, digits, '.', '_' or '-'"
        )
    return case_id


def ensure_contained(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise UnsafeOutputPath(
            f"output path escapes reports directory: {candidate_resolved}"
        ) from exc
    return candidate_resolved


def new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class CaseRun:
    case_id: str
    run_id: str
    reports_root: Path
    run_dir: Path


def create_case_run(reports_root: Path, case_id: str) -> CaseRun:
    safe_case_id = validate_case_id(case_id)
    root = reports_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass

    case_dir = ensure_contained(root, root / safe_case_id)
    case_dir.mkdir(parents=False, exist_ok=True)
    try:
        case_dir.chmod(0o700)
    except OSError:
        pass
    # Re-check after mkdir to catch a pre-existing symlink aimed outside Reports.
    case_dir = ensure_contained(root, case_dir)

    for _ in range(10):
        run_id = new_run_id()
        run_dir = ensure_contained(root, case_dir / run_id)
        try:
            run_dir.mkdir(parents=False, exist_ok=False)
        except FileExistsError:
            continue
        try:
            run_dir.chmod(0o700)
        except OSError:
            pass
        return CaseRun(safe_case_id, run_id, root, run_dir)
    raise TriageRunCollision("could not allocate a unique run directory")


class TriageRunCollision(RuntimeError):
    pass
