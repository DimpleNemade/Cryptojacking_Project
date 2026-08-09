"""Strict schema validation, atomic output writes, and bundle verification."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

from .hashing import sha256_file

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SCHEMA_VERSIONS = {"manifest": "1.0.0", "summary": "1.0.0", "findings": "1.0.0"}


def load_schema(kind: str) -> dict[str, Any]:
    if kind not in SCHEMA_VERSIONS:
        raise ValueError(f"unknown schema kind: {kind}")
    path = SCHEMA_DIR / f"{kind}-{SCHEMA_VERSIONS[kind]}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_document(kind: str, document: Any) -> tuple[bool, list[str]]:
    schema = load_schema(kind)
    validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    formatted = [f"{list(error.path)}: {error.message}" for error in errors]
    return not formatted, formatted


def require_valid_document(kind: str, document: Any) -> None:
    valid, errors = validate_document(kind, document)
    if not valid:
        raise ValueError(f"generated {kind} failed schema validation: {'; '.join(errors)}")


def _atomic_write(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            pass


def atomic_write_json(path: Path, data: Any) -> None:
    def write(handle: Any) -> None:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")

    _atomic_write(path, write)


def atomic_write_text(path: Path, text: str) -> None:
    _atomic_write(path, lambda handle: handle.write(text))


def hash_file_sha256(path: Path) -> str:
    return sha256_file(path)


def verify_artifact_hashes(manifest_path: Path, manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    """Verify sibling artifacts named in a manifest without following path escapes."""

    errors: list[str] = []
    report_dir = manifest_path.resolve().parent
    records = manifest.get("outputs", {}).get("artifact_hashes", [])
    if not records:
        return False, ["manifest contains no artifact hashes"]
    for record in records:
        name = record.get("name")
        expected = record.get("sha256")
        if not isinstance(name, str) or Path(name).name != name:
            errors.append(f"unsafe artifact name: {name!r}")
            continue
        target = (report_dir / name).resolve()
        try:
            target.relative_to(report_dir)
        except ValueError:
            errors.append(f"artifact escapes report directory: {name}")
            continue
        if not target.is_file():
            errors.append(f"artifact missing: {name}")
            continue
        actual = sha256_file(target)
        if actual != expected:
            errors.append(f"artifact hash mismatch: {name}")
    return not errors, errors
