"""Command-line contract for the offline cryptojacking indicator-triage tool.

Exit codes: 0 clean completed scan, 10 completed scan with findings, 20 partial
or failed analysis, 30 integrity failure, 64 usage/configuration, 70 internal.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .case import create_case_run, validate_case_id
from .engine import (
    ENGINE_NAME,
    ENGINE_VERSION,
    MAX_MATCHED_VALUE_CHARACTERS,
    ScanError,
    compile_rules,
    rule_file_hashes,
    scan_file,
)
from .evidence import inspect_after, inspect_before, write_access_advisory
from .findings import LIMITATION as LIMITATION_TEXT
from .findings import build_findings
from .manifest import ManifestInput, build_manifest, output_hashes, write_manifest
from .reporting import (
    atomic_write_json,
    atomic_write_text,
    load_schema,
    require_valid_document,
    validate_document,
    verify_artifact_hashes,
)
from .reporting_ext import SummaryInput, build_summary, write_summary
from .strings_extractor import ExtractionTimeout, StringResult, extract_strings_file

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
DEFAULT_LIMITS = {
    "total_timeout_seconds": 120.0,
    "max_input_bytes": 200_000_000,
    "max_yara_matches": 5_000,
    "max_extracted_strings": 5_000,
    "max_extracted_string_bytes": 2_000_000,
    "max_single_string_bytes": 4_096,
    "max_matched_value_characters": MAX_MATCHED_VALUE_CHARACTERS,
}

EXIT_OK_NO_FINDINGS = 0
EXIT_OK_FINDINGS = 10
EXIT_PARTIAL = 20
EXIT_INTEGRITY = 30
EXIT_USAGE = 64
EXIT_INTERNAL = 70


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_version() -> str:
    try:
        return version("cryptojacking-forensics")
    except PackageNotFoundError:
        return "0.1.0a2"


def _positive_timeout(value: str) -> float:
    parsed = float(value)
    if parsed <= 0 or parsed > 86_400:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 86400")
    return parsed


def _minimum_length(value: str) -> int:
    parsed = int(value)
    if parsed < 4 or parsed > 128:
        raise argparse.ArgumentTypeError("min-length must be between 4 and 128")
    return parsed


def _resolve_rule_files(rules_path: Path) -> list[Path]:
    if rules_path.is_file() and rules_path.suffix.lower() in {".yar", ".yara"}:
        return [rules_path.resolve()]
    if not rules_path.is_dir():
        return []
    return sorted(
        [*rules_path.glob("*.yar"), *rules_path.glob("*.yara")],
        key=lambda path: path.name,
    )


def _exit_for_status(analysis_status: str, hash_verification: str, has_findings: bool) -> int:
    if hash_verification == "FAIL" or analysis_status == "INTEGRITY_FAILURE":
        return EXIT_INTEGRITY
    if analysis_status in {"FAILED", "PARTIAL"}:
        return EXIT_PARTIAL
    return EXIT_OK_FINDINGS if has_findings else EXIT_OK_NO_FINDINGS


def _analysis_status(stages: dict[str, str], hash_verification: str) -> str:
    if hash_verification == "FAIL":
        return "INTEGRITY_FAILURE"
    values = list(stages.values())
    if not any(value in {"SUCCESS", "PARTIAL"} for value in values):
        return "FAILED"
    if any(value != "SUCCESS" for value in values):
        return "PARTIAL"
    return "SUCCESS"


def cmd_scan(args: argparse.Namespace) -> int:
    started_at = _utcnow()
    deadline = time.monotonic() + args.timeout
    try:
        validate_case_id(args.case_id)
        evidence = inspect_before(Path(args.input))
        case_run = create_case_run(Path(args.output), args.case_id)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    warnings: list[str] = []
    errors: list[str] = []
    stages = {"scan": "SKIPPED", "strings": "SKIPPED"}
    findings_input: list[dict[str, Any]] = []
    strings_result = StringResult(entries=[])
    oversized = bool(
        evidence.size is not None and evidence.size > DEFAULT_LIMITS["max_input_bytes"]
    )
    rules_path = Path(args.rules) if args.rules else DEFAULT_RULES_DIR
    rule_files = _resolve_rule_files(rules_path)

    if oversized:
        errors.append(f"input exceeds max_input_bytes ({DEFAULT_LIMITS['max_input_bytes']})")
    else:
        if not rule_files:
            warnings.append("no YARA rule files found; YARA stage skipped")
        else:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stages["scan"] = "FAILED"
                    errors.append("total analysis deadline exceeded before YARA scan")
                else:
                    rules = compile_rules(rule_files)
                    result = scan_file(
                        rules,
                        evidence.path,
                        timeout_seconds=remaining,
                        max_matches=int(DEFAULT_LIMITS["max_yara_matches"]),
                    )
                    stages["scan"] = result.status
                    findings_input.extend(
                        {
                            "rule_id": match.rule_id,
                            "rule_name": match.rule_name,
                            "source": "yara",
                            "matched_indicator": match.matched_value,
                            "offset": match.offset,
                        }
                        for match in result.matches
                    )
                    if result.error:
                        errors.append(result.error)
                    if result.truncated:
                        warnings.append("YARA match limit reached; results truncated")
            except ScanError as exc:
                stages["scan"] = "FAILED"
                errors.append(str(exc))

        try:
            if time.monotonic() >= deadline:
                raise ExtractionTimeout("total analysis deadline exceeded before strings stage")
            strings_result = extract_strings_file(
                evidence.path,
                min_length=args.min_length,
                max_strings=int(DEFAULT_LIMITS["max_extracted_strings"]),
                max_bytes=int(DEFAULT_LIMITS["max_extracted_string_bytes"]),
                max_string_bytes=int(DEFAULT_LIMITS["max_single_string_bytes"]),
                deadline=deadline,
            )
            stages["strings"] = "PARTIAL" if strings_result.truncated else "SUCCESS"
            if strings_result.truncated:
                warnings.append("string output limit reached; results truncated")
        except (ExtractionTimeout, OSError, ValueError) as exc:
            stages["strings"] = "FAILED"
            errors.append(str(exc))

    try:
        inspect_after(evidence)
        write_access_advisory(evidence)
    except OSError as exc:
        evidence.hash_verification = "FAIL"
        evidence.external_modification = "UNKNOWN"
        errors.append(f"post-analysis evidence verification failed: {exc}")

    if evidence.hash_verification == "FAIL":
        errors.append("evidence identity or SHA-256 changed during analysis")

    analysis_status = _analysis_status(stages, evidence.hash_verification)
    findings = build_findings(
        findings_input,
        strings_result,
        evidence.path.name,
        include_raw_indicators=args.raw,
    )
    run_dir = case_run.run_dir
    findings_path = run_dir / "findings.json"
    summary_path = run_dir / "summary.json"
    manifest_path = run_dir / "manifest.json"
    strings_path = run_dir / "strings.txt"

    findings_doc = {
        "schema_version": "1.0.0",
        "findings": [finding.to_dict() for finding in findings],
    }
    summary = build_summary(
        SummaryInput(
            case_id=args.case_id,
            run_id=case_run.run_id,
            analysis_status=analysis_status,
            hash_verification=evidence.hash_verification,
            input_sha256_before=evidence.sha256_before,
            input_sha256_after=evidence.sha256_after,
            findings=findings,
            warnings=warnings,
            errors=errors,
            limitations=[LIMITATION_TEXT],
        )
    )
    require_valid_document("findings", findings_doc)
    require_valid_document("summary", summary)
    atomic_write_json(findings_path, findings_doc)
    write_summary(summary_path, summary)
    immutable_outputs = [findings_path, summary_path]
    if args.raw:
        atomic_write_text(strings_path, "\n".join(strings_result.strings) + "\n")
        immutable_outputs.append(strings_path)

    pack_digest, rule_records = rule_file_hashes(rule_files)
    effective_limits = {
        **DEFAULT_LIMITS,
        "total_timeout_seconds": args.timeout,
        "min_string_length": args.min_length,
    }
    manifest = build_manifest(
        ManifestInput(
            case_id=args.case_id,
            run_id=case_run.run_id,
            started_at=started_at,
            finished_at=_utcnow(),
            analysis_status=analysis_status,
            evidence={
                "input_file": str(evidence.path) if args.raw else None,
                "input_file_display": evidence.display_name,
                "size": evidence.size,
                "sha256_before": evidence.sha256_before,
                "sha256_after": evidence.sha256_after,
                "hash_verification": evidence.hash_verification,
                "opened_read_only": evidence.opened_read_only,
                "accessed_at": evidence.accessed_at,
                "identity_before": {
                    "device": evidence.stat_device_before,
                    "inode": evidence.stat_inode_before,
                    "size": evidence.stat_size_before,
                    "mtime": evidence.stat_mtime_before,
                },
                "identity_after": {
                    "device": evidence.stat_device_after,
                    "inode": evidence.stat_inode_after,
                    "size": evidence.stat_size_after,
                    "mtime": evidence.stat_mtime_after,
                },
                "observed_controls": evidence.observed_controls,
                "control_limitations": evidence.control_limitations,
                "external_modification": evidence.external_modification,
            },
            engine={"name": ENGINE_NAME, "version": ENGINE_VERSION, "package": "yara-python"},
            rule_pack={
                "name": "cryptojacking-forensics-alpha",
                "version": "1.0.0",
                "digest": pack_digest,
                "rule_file_count": len(rule_files),
                "files": rule_records,
            },
            limits=effective_limits,
            stages=stages,
            warnings=warnings,
            errors=errors,
            truncation={
                "scan_truncated": stages["scan"] == "PARTIAL",
                "strings_truncated": strings_result.truncated,
            },
            outputs={
                "report_dir": str(run_dir) if args.raw else None,
                "privacy_mode": "raw-opt-in" if args.raw else "safe",
                "artifact_hashes": output_hashes(immutable_outputs),
            },
            limitations=[LIMITATION_TEXT],
            tool_version=_get_version(),
        )
    )
    require_valid_document("manifest", manifest)
    write_manifest(manifest_path, manifest)

    display_dir = str(run_dir) if args.raw else f"{args.case_id}/{case_run.run_id}"
    if args.format == "json":
        print(
            json.dumps(
                {"summary": summary, "findings": findings_doc, "report_dir": display_dir},
                indent=2,
                sort_keys=True,
            )
        )
    if not args.quiet:
        print(
            f"Analysis complete: {display_dir} (status={analysis_status})",
            file=sys.stderr,
        )
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return _exit_for_status(analysis_status, evidence.hash_verification, bool(findings))


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: dict[str, Any] = {
        "tool": {"name": "cryptojacking-forensics", "version": _get_version()},
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION, "package": "yara-python"},
        "platform": sys.platform,
        "python": sys.version.split()[0],
    }
    errors: list[str] = []
    rule_files = _resolve_rule_files(DEFAULT_RULES_DIR)
    try:
        compile_rules(rule_files)
        rule_status = "OK"
    except ScanError as exc:
        rule_status = "FAILED"
        errors.append(str(exc))
    checks["rule_pack"] = {
        "version": "1.0.0",
        "status": rule_status,
        "rule_file_count": len(rule_files),
        "rule_files": [path.name for path in rule_files],
    }
    try:
        for kind in ("manifest", "summary", "findings"):
            load_schema(kind)
        checks["schemas"] = {
            "status": "OK",
            "versions": {kind: "1.0.0" for kind in ("manifest", "summary", "findings")},
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        checks["schemas"] = {"status": "FAILED"}
        errors.append(str(exc))
    checks["errors"] = errors
    if args.format == "json":
        print(json.dumps(checks, indent=2, sort_keys=True))
    else:
        for key, value in checks.items():
            print(f"{key}: {json.dumps(value)}", file=sys.stderr)
        print("doctor: " + ("OK" if not errors else "FAILED"), file=sys.stderr)
    return EXIT_OK_NO_FINDINGS if not errors else EXIT_PARTIAL


def cmd_rules_check(args: argparse.Namespace) -> int:
    rules_path = Path(args.rules) if args.rules else DEFAULT_RULES_DIR
    rule_files = _resolve_rule_files(rules_path)
    ok = bool(rule_files)
    report: dict[str, Any] = {"rules_path": str(rules_path), "rules": []}
    if not rule_files:
        report["error"] = "no .yar or .yara files found"
    for rule_file in rule_files:
        entry: dict[str, Any] = {"name": rule_file.name}
        try:
            compile_rules([rule_file])
            entry["compiles"] = True
        except ScanError as exc:
            ok = False
            entry.update({"compiles": False, "error": str(exc)})
        report["rules"].append(entry)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for entry in report["rules"]:
            print(
                f"  {entry['name']}: {'OK' if entry.get('compiles') else 'FAIL'}",
                file=sys.stderr,
            )
        print("rules check: " + ("OK" if ok else "FAILED"), file=sys.stderr)
    return EXIT_OK_NO_FINDINGS if ok else EXIT_USAGE


def _report_kind(document: Any) -> str | None:
    if not isinstance(document, dict):
        return None
    if "tool" in document and "evidence" in document and "outputs" in document:
        return "manifest"
    if "findings" in document and "schema_version" in document:
        return "findings"
    if "evidence_strength" in document and "analysis_status" in document:
        return "summary"
    return None


def cmd_verify_report(args: argparse.Namespace) -> int:
    target = Path(args.report)
    if target.is_dir():
        target = target / "manifest.json"
    if not target.is_file():
        print(f"ERROR: report not found: {target}", file=sys.stderr)
        return EXIT_USAGE
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: invalid report JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    kind = _report_kind(document)
    if kind is None:
        print("ERROR: unrecognized report document", file=sys.stderr)
        return EXIT_USAGE
    schema_valid, errors = validate_document(kind, document)
    valid = schema_valid
    artifact_hashes_valid: bool | None = None
    if valid and kind == "manifest":
        artifact_hashes_valid, hash_errors = verify_artifact_hashes(target, document)
        errors.extend(hash_errors)
        valid = valid and artifact_hashes_valid
    result = {
        "kind": kind,
        "schema_valid": schema_valid,
        "artifact_hashes_valid": artifact_hashes_valid,
        "valid": valid,
        "errors": errors,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    print(f"verify-report: {kind} {'VALID' if valid else 'INVALID'}", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    if valid:
        return EXIT_OK_NO_FINDINGS
    return EXIT_INTEGRITY if artifact_hashes_valid is False else EXIT_INTERNAL


def _cmd_version(_args: argparse.Namespace) -> int:
    print(_get_version())
    return EXIT_OK_NO_FINDINGS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cj-triage",
        description="Offline, evidence-aware cryptojacking indicator-triage CLI.",
    )
    parser.add_argument(
        "--version", action="version", version=f"cryptojacking-forensics {_get_version()}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a supplied artifact")
    scan_parser.add_argument("target_type", choices=["artifact"])
    scan_parser.add_argument("input", help="path to the artifact")
    scan_parser.add_argument("--case-id", required=True)
    scan_parser.add_argument("--output", default="Reports")
    scan_parser.add_argument("--rules", default=None)
    scan_parser.add_argument("--timeout", type=_positive_timeout, default=120.0)
    scan_parser.add_argument("--min-length", type=_minimum_length, default=4)
    scan_parser.add_argument("--format", choices=["human", "json"], default="human")
    scan_parser.add_argument("--raw", action="store_true", help="include raw strings and paths")
    scan_parser.add_argument("--quiet", action="store_true", help="suppress completion message")
    scan_parser.set_defaults(func=cmd_scan)

    doctor_parser = subparsers.add_parser("doctor", help="validate environment and assets")
    doctor_parser.add_argument("--format", choices=["human", "json"], default="human")
    doctor_parser.set_defaults(func=cmd_doctor)

    rules_parser = subparsers.add_parser("rules", help="rule-pack operations")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    check_parser = rules_subparsers.add_parser("check", help="compile-check rules")
    check_parser.add_argument("--rules", default=None)
    check_parser.add_argument("--format", choices=["human", "json"], default="human")
    check_parser.set_defaults(func=cmd_rules_check)

    verify_parser = subparsers.add_parser("verify-report", help="verify a report or bundle")
    verify_parser.add_argument("report")
    verify_parser.add_argument("--format", choices=["human", "json"], default="human")
    verify_parser.set_defaults(func=cmd_verify_report)

    version_parser = subparsers.add_parser("version", help="print version")
    version_parser.set_defaults(func=_cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code in (0, None):
            raise
        return EXIT_USAGE
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - CLI safety boundary
        print(f"ERROR: internal failure: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
