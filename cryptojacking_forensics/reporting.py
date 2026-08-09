"""Schema validation and atomic report writing."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

try:
    import jsonschema  # type: ignore

    _HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover
    _HAVE_JSONSCHEMA = False

from .hashing import sha256_file

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SCHEMA_VERSIONS = {
    "manifest": "1.0.0",
    "summary": "1.0.0",
    "findings": "1.0.0",
}


def load_schema(kind: str) -> dict[str, Any]:
    path = SCHEMA_DIR / f"{kind}-{SCHEMA_VERSIONS[kind]}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_document(kind: str, document: Any) -> tuple[bool, list[str]]:
    """Validate a document against its versioned schema.

    Returns (ok, errors). If jsonschema is unavailable, we fall back to a basic
    structural check (schema_version + required top-level keys) so the verification
    command still runs in minimal environments.
    """
    errors: list[str] = []
    schema = load_schema(kind)
    if _HAVE_JSONSCHEMA:
        validator = jsonschema.Draft7Validator(schema)
        errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(document)]
        return (len(errors) == 0), errors

    # Fallback structural check.
    required = schema.get("required", [])
    if not isinstance(document, dict):
        return False, ["document is not an object"]
    for key in required:
        if key not in document:
            errors.append(f"missing required key: {key}")
    return (len(errors) == 0), errors


def atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON atomically: write to a temp file then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
        # Restrictive permissions where supported (owner-only read/write).
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if Path(tmp).exists():
            try:
                os.unlink(tmp)
            except OSError:
                pass


def hash_file_sha256(path: Path) -> str:
    return sha256_file(path)
