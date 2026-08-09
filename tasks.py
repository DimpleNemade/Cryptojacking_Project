#!/usr/bin/env python3
"""Convenience task runner for cj-triage development.

All tasks are thin wrappers around standard commands. Raw commands are shown so the
runner is convenience only and never hides behavior.

Usage:  python tasks.py <task>
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> int:
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=ROOT)


def setup() -> int:
    return _run([sys.executable, "-m", "pip", "install", "-e", ".[dev]"])


def test() -> int:
    return _run([sys.executable, "-m", "pytest", "-ra"])


def lint() -> int:
    return _run([sys.executable, "-m", "ruff", "check", "cryptojacking_forensics", "tests"])


def build() -> int:
    return _run([sys.executable, "-m", "build", "--wheel"])


def run_safe_fixture() -> int:
    return _run(
        [
            sys.executable,
            "-m",
            "cryptojacking_forensics",
            "scan",
            "artifact",
            "tests/fixtures/synthetic_miner_indicators.txt",
            "--case-id",
            "TASKRUN",
        ]
    )


def validate() -> int:
    rc = 0
    rc |= _run([sys.executable, "-m", "cryptojacking_forensics", "doctor"])
    rc |= _run([sys.executable, "-m", "cryptojacking_forensics", "rules", "check"])
    rc |= _run([sys.executable, "-m", "pytest", "-ra"])
    return rc


TASKS = {
    "help": None,
    "setup": setup,
    "test": test,
    "lint": lint,
    "build": build,
    "run-safe-fixture": run_safe_fixture,
    "validate": validate,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("help", "-h", "--help"):
        print("Available tasks:")
        for name in TASKS:
            print(f"  {name}")
        return 0
    task = TASKS.get(argv[0])
    if task is None:
        print(f"Unknown task: {argv[0]}")
        return 2
    return task()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
