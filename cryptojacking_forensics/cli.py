from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

from .case import create_case_run, validate_case_id
from .commands import CommandResult, run_command, summarize_stderr, utc_now
from .evidence import inspect_after, inspect_before
from .errors import TriageError
from .findings import LIMITATION, build_findings, overall_severity
from .hashing import sha256_file
from .manifest import write_json
from .reporting import write_summary_json, write_summary_text
from .strings_extractor import extract_strings
from .yara_scanner import scan_with_yara

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS_ROOT = PROJECT_ROOT / "Reports"
DEFAULT_RULES_ROOT = PROJECT_ROOT / "YARA_Rules"


def _tool_version(
    command: list[str], timeout_seconds: float = 5
) -> tuple[str, CommandResult]:
    result = run_command(command, timeout_seconds)
    if not result.succeeded:
        version = f"UNAVAILABLE ({summarize_stderr(result.stderr) or 'non-zero exit'})"
        return version, result
    lines = (result.stdout or result.stderr).strip().splitlines()
    return (lines[0] if lines else "UNKNOWN"), result


def _analysis_status(
    results: list[CommandResult], hash_verification: str, *, incomplete: bool = False
) -> str:
    if hash_verification != "PASS":
        return "INTEGRITY_FAILURE"
    successes = sum(result.succeeded for result in results)
    if successes == len(results) and not incomplete:
        return "SUCCESS"
    return "PARTIAL" if successes else "FAILED"


def _score(independent_indicator_count: int) -> int:
    # Retained only for continuity with the prototype; it is not validated.
    return min(independent_indicator_count, 10)


def run_pipeline(
    memory_path: Path,
    case_id: str,
    *,
    reports_root: Path = DEFAULT_REPORTS_ROOT,
    rules_root: Path = DEFAULT_RULES_ROOT,
    timeout_seconds: float = 120,
) -> Path:
    started_at = utc_now()
    validate_case_id(case_id)
    evidence = inspect_before(memory_path)
    case_run = create_case_run(reports_root, case_id)
    warnings: list[str] = []
    errors: list[str] = []

    rule_files = sorted(rules_root.resolve().glob("*.yar"))
    rule_file_records = [
        {
            "path": str(path),
            "display_path": path.name,
            "sha256": sha256_file(path),
        }
        for path in rule_files
    ]
    if not rule_files:
        warnings.append(f"No YARA rule files found under {rules_root.resolve()}")

    yara_results = scan_with_yara(evidence.path, rule_files, timeout_seconds)
    strings_result = extract_strings(evidence.path, timeout_seconds)
    command_results = [result for _, result in yara_results] + [strings_result]

    for result in command_results:
        if not result.succeeded:
            errors.append(
                f"Command failed (return code {result.return_code}): "
                f"{' '.join(result.command)}; {summarize_stderr(result.stderr)}"
            )
        elif result.stderr.strip():
            warnings.append(
                f"Command warning ({' '.join(result.command)}): "
                f"{summarize_stderr(result.stderr)}"
            )

    try:
        inspect_after(evidence)
    except OSError as exc:
        evidence.hash_verification = "FAIL"
        errors.append(f"Post-analysis evidence hashing failed: {exc}")
    if evidence.hash_verification != "PASS" and evidence.sha256_after is not None:
        errors.append("Evidence SHA-256 changed between pre-analysis and post-analysis hashing")

    analysis_status = _analysis_status(
        command_results,
        evidence.hash_verification,
        incomplete=not rule_files,
    )
    successful_yara_outputs = [
        (str(rule_file), result.stdout)
        for rule_file, result in yara_results
        if result.succeeded
    ]
    findings = build_findings(
        successful_yara_outputs,
        strings_result.stdout if strings_result.succeeded else "",
        str(evidence.path),
    )

    yara_version, yara_version_result = _tool_version(["yara", "--version"])
    strings_version, strings_version_result = _tool_version(["strings", "--version"])
    version_results = [yara_version_result, strings_version_result]
    for result in version_results:
        if not result.succeeded:
            warnings.append(
                f"Could not determine tool version ({' '.join(result.command)}): "
                f"{summarize_stderr(result.stderr)}"
            )

    yara_output_path = case_run.run_dir / "yara.txt"
    strings_output_path = case_run.run_dir / "strings.txt"
    findings_path = case_run.run_dir / "findings.json"
    summary_json_path = case_run.run_dir / "summary.json"
    summary_text_path = case_run.run_dir / "summary.txt"
    manifest_path = case_run.run_dir / "manifest.json"

    yara_output_path.write_text(
        "\n".join(
            f"# RULE_FILE={rule_file}\n{result.stdout}"
            for rule_file, result in yara_results
        ),
        encoding="utf-8",
    )
    strings_output_path.write_text(strings_result.stdout, encoding="utf-8")
    write_json(findings_path, [finding.to_dict() for finding in findings])

    severity = overall_severity(findings) if analysis_status == "SUCCESS" else "UNDETERMINED"
    independent_indicator_count = sum(
        finding.independent_indicator for finding in findings
    )
    summary = {
        "case_id": case_run.case_id,
        "run_id": case_run.run_id,
        "analysis_status": analysis_status,
        "hash_verification": evidence.hash_verification,
        "input_sha256_before": evidence.sha256_before,
        "input_sha256_after": evidence.sha256_after,
        "finding_count": len(findings),
        "independent_indicator_count": independent_indicator_count,
        "risk_severity": severity,
        "unvalidated_triage_score": (
            _score(independent_indicator_count)
            if analysis_status == "SUCCESS"
            else None
        ),
        "explanation": (
            "Analysis incomplete; absence of findings must not be interpreted as clean."
            if analysis_status != "SUCCESS"
            else (
                f"{len(findings)} triage findings were grouped into "
                f"{independent_indicator_count} independent indicator groups; "
                "review findings.json."
                if findings
                else "No miner indicators were found by the completed triage analyses."
            )
        ),
        "warnings": warnings,
        "errors": errors,
        "limitations": LIMITATION,
    }
    write_summary_json(summary_json_path, summary)
    write_summary_text(summary_text_path, summary)

    output_paths = [
        yara_output_path,
        strings_output_path,
        findings_path,
        summary_json_path,
        summary_text_path,
    ]
    recorded_commands = command_results + version_results
    finished_at = utc_now()
    manifest = {
        "case_id": case_run.case_id,
        "run_id": case_run.run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "analysis_status": analysis_status,
        "input_file": str(evidence.path),
        "input_file_display": evidence.path.name,
        "input_file_size": evidence.size,
        "input_sha256_before": evidence.sha256_before,
        "input_sha256_after": evidence.sha256_after,
        "hash_verification": evidence.hash_verification,
        "commands_executed": [result.manifest_record() for result in recorded_commands],
        "command_return_codes": [result.return_code for result in recorded_commands],
        "stderr_summaries": [
            summarize_stderr(result.stderr) for result in recorded_commands if result.stderr
        ],
        "tool_versions": {
            "python": platform.python_version(),
            "yara": yara_version,
            "strings": strings_version,
            "hashing": "Python hashlib.sha256",
        },
        "yara_rule_files": rule_file_records,
        "output_files": [
            {
                "path": str(path),
                "display_path": str(path.relative_to(case_run.reports_root)),
                "sha256": sha256_file(path),
            }
            for path in output_paths
        ],
        "path_disclosure_notice": (
            "Traceability fields and recorded commands may contain absolute local paths. "
            "Use display_path or input_file_display when workstation layout should not "
            "be disclosed."
        ),
        "warnings": warnings,
        "errors": errors,
        "limitations": LIMITATION,
    }
    write_json(manifest_path, manifest)
    return case_run.run_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cryptojacking indicator triage over a captured evidence file."
    )
    parser.add_argument("-m", "--memory", required=True, type=Path, help="Evidence file")
    parser.add_argument("-c", "--case-id", required=True, help="Safe case identifier")
    parser.add_argument(
        "--timeout",
        type=float,
        default=120,
        help="Per-command timeout in seconds (default: 120)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        print("ERROR: --timeout must be greater than zero", file=sys.stderr)
        return 2
    try:
        run_dir = run_pipeline(args.memory, args.case_id, timeout_seconds=args.timeout)
    except (TriageError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Analysis complete: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
