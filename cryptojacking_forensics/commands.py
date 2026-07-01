from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from time import monotonic


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    def manifest_record(self) -> dict[str, object]:
        record = asdict(self)
        record["stdout_summary"] = summarize_text(self.stdout)
        record.pop("stdout")
        record["stderr_summary"] = summarize_stderr(self.stderr)
        record.pop("stderr")
        return record


def summarize_stderr(stderr: str, limit: int = 500) -> str:
    return summarize_text(stderr, limit)


def summarize_text(value: str, limit: int = 500) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def run_command(args: list[str], timeout_seconds: float) -> CommandResult:
    if not args or not all(isinstance(arg, str) for arg in args):
        raise ValueError("command must be a non-empty list of strings")
    started_at = utc_now()
    started = monotonic()
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            shell=False,
            timeout=timeout_seconds,
            check=False,
        )
        return_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        return_code = 124
        stdout = _timeout_text(exc.stdout)
        stderr = _timeout_text(exc.stderr) or f"command timed out after {timeout_seconds}s"
        timed_out = True
    except FileNotFoundError as exc:
        return_code = 127
        stdout = ""
        stderr = str(exc)
        timed_out = False
    finished_at = utc_now()
    return CommandResult(
        command=list(args),
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=round(monotonic() - started, 6),
        timed_out=timed_out,
    )


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value
