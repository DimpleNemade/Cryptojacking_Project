class TriageError(Exception):
    """Base exception for expected triage failures."""


class InvalidCaseID(TriageError, ValueError):
    """Raised when a case identifier is unsafe."""


class UnsafeOutputPath(TriageError):
    """Raised when an output path escapes the reports root."""

