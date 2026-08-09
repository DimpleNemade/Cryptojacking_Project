"""cryptojacking-forensics CLI.

Stable automation contract (see docs/project-roadmap.html and AGENTS.md):
  0  completed successfully, no findings
  10 completed successfully, findings present
  20 incomplete or partial analysis
  30 evidence integrity failure
  64 command usage or configuration error
  70 internal or unrecoverable execution failure

Privacy defaults: raw evidence strings and absolute paths are NOT written unless
the operator explicitly opts in with --raw. Machine-readable output goes to stdout
only when --format json is requested; progress/diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .case import create_case_run, validate_case_id
from .engine import ENGINE_NAME, ENGINE_VERSION, ScanError, compile_rules, rule_file_hashes, scan_bytes
from .evidence import inspect_after, inspect_before, write_access_advisory
from .findings import LIMITATION as LIMITATION_TEXT, build_findings
from .reporting import atomic_write_json, validate_document
from .reporting_ext import build_summary, write_summary, SummaryInput
from .manifest import build_manifest, output_hashes, write_manifest, ManifestInput
from .strings_extractor import extract_strings

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
DEFAULT_LIMITS = {
    "total_timeout_seconds": 120,
    "max_input_bytes": 200_000_000,
    "max_matches": 5_000,
    "max_output_bytes": 2_000_000,
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
        from importlib.metadata import version as _v

        return _v("cryptojacking-forensics")
    except Exception:
        return "0.1.0a1"


def _resolve_rule_files(rules_dir: Path) -> list[Path]:
    if not rules_dir.exists():
        return []
    return sorted(rules_dir.glob("*.yar"))


def _budget_ms(per_stage_seconds: float) -> int:
    return max(100, int(per_stage_seconds * 1000))


def _exit_for_status(analysis_status: str, hash_verification: str, has_findings: bool) -> int:
    if hash_verification == "FAIL":
        return EXIT_INTEGRITY
    if analysis_status == "INTEGRITY_FAILURE":
        return EXIT_INTEGRITY
    if analysis_status == "FAILED":
        return EXIT_PARTIAL
    if analysis_status == "PARTIAL":
        return EXIT_PARTIAL
    # SUCCESS
    return EXIT_OK_FINDINGS if has_findings else EXIT_OK_NO_FINDINGS


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        validate_case_id(args.case_id)
        evidence = inspect_before(Path(args.input))
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    warnings: list[str] = []
    errors: list[str] = []

    if evidence.size is not None and evidence.size > DEFAULT_LIMITS["max_input_bytes"]:
        errors.append(f"input exceeds max_input_bytes ({DEFAULT_LIMITS['max_input_bytes']})")
        return EXIT_PARTIAL

    rule_files = _resolve_rule_files(Path(args.rules) if args.rules else DEFAULT_RULES_DIR)
    if not rule_files:
        warnings.append("no YARA rule files found; scanning with string indicators only")

    try:
        data = evidence.path.read_bytes()
    except OSError as exc:
        errors.append(f"could not read input: {exc}")
        return EXIT_PARTIAL

    stages: dict[str, str] = {}
    findings_input: list[dict[str, Any]] = []

    scan_status = "SUCCESS"
    try:
        rules = compile_rules(rule_files)
        result = scan_bytes(
            rules,
            data,
            timeout_ms=_budget_ms(args.timeout),
            max_matches=DEFAULT_LIMITS["max_matches"],
        )
        scan_status = result.status
        for m in result.matches:
            findings_input.append(
                {
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "source": "yara",
                    "matched_indicator": m.matched_value,
                    "offset": m.offset,
                }
            )
        if result.error:
            errors.append(result.error)
        if result.truncated:
            warnings.append("scan match limit reached; results truncated")
    except ScanError as exc:
        scan_status = "FAILED"
        errors.append(str(exc))

    strings_result = extract_strings(
        data,
        min_length=args.min_length,
        max_strings=DEFAULT_LIMITS["max_matches"],
        max_bytes=DEFAULT_LIMITS["max_output_bytes"],
    )
    strings_status = "PARTIAL" if strings_result.truncated else "SUCCESS"

    stages["scan"] = scan_status
    stages["strings"] = strings_status

    try:
        inspect_after(evidence)
        write_access_advisory(evidence)
    except OSError as exc:
        evidence.hash_verification = "FAIL"
        errors.append(f"post-analysis evidence hashing failed: {exc}")

    if evidence.hash_verification == "FAIL" and evidence.sha256_after is not None:
        errors.append("evidence SHA-256 changed between pre/post hashing")

    if evidence.hash_verification == "FAIL":
        analysis_status = "INTEGRITY_FAILURE"
    elif scan_status == "FAILED":
        analysis_status = "FAILED"
    elif scan_status == "PARTIAL" or strings_status == "PARTIAL" or (not rule_files):
        analysis_status = "PARTIAL"
    else:
        analysis_status = "SUCCESS"

    findings = build_findings(findings_input, strings_result, evidence.path.name)

    case_run = create_case_run(Path(args.output), args.case_id)
    run_dir = case_run.run_dir

    pack_digest, _rule_records = rule_file_hashes(rule_files)
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
            unvalidated_triage_score=(
                sum(1 for f in findings if f.independent_indicator) if analysis_status == "SUCCESS" else None
            ),
        )
    )

    findings_doc = [f.to_dict() for f in findings]
    manifest = build_manifest(
        ManifestInput(
            case_id=args.case_id,
            run_id=case_run.run_id,
            started_at=_utcnow(),
            finished_at=_utcnow(),
            analysis_status=analysis_status,
            evidence={
                "input_file": (str(evidence.path) if args.raw else None),
                "input_file_display": evidence.display_name,
                "size": evidence.size,
                "sha256_before": evidence.sha256_before,
                "sha256_after": evidence.sha256_after,
                "hash_verification": evidence.hash_verification,
                "opened_read_only": evidence.opened_read_only,
                "accessed_at": evidence.accessed_at,
                "observed_controls": evidence.observed_controls,
                "control_limitations": evidence.control_limitations,
                "external_modification": evidence.external_modification,
            },
            engine={"name": ENGINE_NAME, "version": ENGINE_VERSION, "package": "yara-python"},
            rule_pack={"name": "cryptojacking-forensics-alpha", "version": "1.0.0", "digest": pack_digest, "rule_count": len(rule_files)},
            limits=DEFAULT_LIMITS,
            stages=stages,
            warnings=warnings,
            errors=errors,
            truncation={"scan_truncated": scan_status == "PARTIAL", "strings_truncated": strings_result.truncated},
            outputs={"report_dir": str(run_dir), "privacy_mode": ("raw-opt-in" if args.raw else "safe")},
            limitations=[LIMITATION_TEXT],
        )
    )

    findings_path = run_dir / "findings.json"
    summary_path = run_dir / "summary.json"
    manifest_path = run_dir / "manifest.json"
    strings_path = run_dir / "strings.txt"

    atomic_write_json(findings_path, findings_doc)
    write_summary(summary_path, summary)
    write_manifest(manifest_path, manifest)
    if args.raw:
        strings_path.write_text("\n".join(strings_result.strings), encoding="utf-8")

    artifact_hashes = output_hashes([findings_path, summary_path, manifest_path])
    manifest["outputs"]["artifact_hashes"] = artifact_hashes
    write_manifest(manifest_path, manifest)

    if args.format == "json":
        payload = {"summary": summary, "findings": findings_doc, "report_dir": str(run_dir)}
        print(json.dumps(payload, indent=2, sort_keys=True))

    print(f"Analysis complete: {run_dir} (status={analysis_status})", file=sys.stderr)
    return _exit_for_status(analysis_status, evidence.hash_verification, bool(findings))


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: dict[str, Any] = {"tool": {"name": "cryptojacking-forensics", "version": _get_version()}}
    checks["engine"] = {"name": ENGINE_NAME, "version": ENGINE_VERSION, "package": "yara-python"}
    rule_files = _resolve_rule_files(DEFAULT_RULES_DIR)
    checks["rule_pack"] = {"version": "1.0.0", "rule_count": len(rule_files), "rules": [p.name for p in rule_files]}
    checks["schema_versions"] = {"manifest": "1.0.0", "summary": "1.0.0", "findings": "1.0.0"}
    checks["platform"] = sys.platform
    checks["python"] = sys.version.split()[0]
    if args.format == "json":
        print(json.dumps(checks, indent=2, sort_keys=True))
    else:
        for k, v in checks.items():
            print(f"{k}: {json.dumps(v)}", file=sys.stderr)
        print("doctor: OK", file=sys.stderr)
    return EXIT_OK_NO_FINDINGS


def cmd_rules_check(args: argparse.Namespace) -> int:
    rules_dir = Path(args.rules) if args.rules else DEFAULT_RULES_DIR
    rule_files = _resolve_rule_files(rules_dir)
    ok = True
    report: dict[str, Any] = {"rules_dir": str(rules_dir), "rules": []}
    if not rule_files:
        ok = False
        report["error"] = "no .yar files found"
    for rf in rule_files:
        entry = {"name": rf.name}
        try:
            compile_rules([rf])
            entry["compiles"] = True
        except ScanError as exc:
            ok = False
            entry["compiles"] = False
            entry["error"] = str(exc)
        report["rules"].append(entry)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for r in report["rules"]:
            status = "OK" if r.get("compiles") else "FAIL"
            print(f"  {r['name']}: {status}", file=sys.stderr)
        print("rules check: " + ("OK" if ok else "FAILED"), file=sys.stderr)
    return EXIT_OK_NO_FINDINGS if ok else EXIT_USAGE


def cmd_verify_report(args: argparse.Namespace) -> int:
    target = Path(args.report)
    if not target.exists():
        print(f"ERROR: file not found: {target}", file=sys.stderr)
        return EXIT_USAGE
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE

    kind = None
    if isinstance(doc, list):
        kind = "findings"
    elif isinstance(doc, dict):
        if "analysis_status" in doc and "evidence" in doc:
            kind = "manifest"
        elif "evidence_strength" in doc and "analysis_status" in doc:
            kind = "summary"
        elif "schema_version" in doc and "analysis_status" in doc:
            kind = "manifest"
        elif "schema_version" in doc and "evidence_strength" in doc:
            kind = "summary"
    if kind is None:
        print("ERROR: unrecognized report document", file=sys.stderr)
        return EXIT_USAGE

    ok, errs = validate_document(kind, doc)
    if ok:
        print(f"verify-report: {kind} VALID", file=sys.stderr)
        if args.format == "json":
            print(json.dumps({"kind": kind, "valid": True}, indent=2))
        return EXIT_OK_NO_FINDINGS

    print(f"verify-report: {kind} INVALID", file=sys.stderr)
    for e in errs:
        print(f"  - {e}", file=sys.stderr)
    if args.format == "json":
        print(json.dumps({"kind": kind, "valid": False, "errors": errs}, indent=2))
    return EXIT_INTERNAL


def _cmd_version(args: argparse.Namespace) -> int:
    print(_get_version())
    return EXIT_OK_NO_FINDINGS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cj-triage",
        description="Offline, evidence-aware cryptojacking indicator-triage CLI.",
    )
    parser.add_argument("--version", action="version", version=f"cryptojacking-forensics {_get_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a supplied artifact")
    p_scan.add_argument("target_type", choices=["artifact"], help="artifact type (byte scan)")
    p_scan.add_argument("input", help="path to the evidence/artifact file")
    p_scan.add_argument("--case-id", required=True)
    p_scan.add_argument("--output", default="Reports")
    p_scan.add_argument("--rules", default=None)
    p_scan.add_argument("--timeout", type=float, default=120.0)
    p_scan.add_argument("--min-length", type=int, default=4)
    p_scan.add_argument("--format", choices=["human", "json"], default="human")
    p_scan.add_argument("--raw", action="store_true", help="opt-in to raw strings/absolute paths")
    p_scan.add_argument("--quiet", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_doc = sub.add_parser("doctor", help="report environment and versions")
    p_doc.add_argument("--format", choices=["human", "json"], default="human")
    p_doc.set_defaults(func=cmd_doctor)

    p_rules = sub.add_parser("rules", help="rule-pack operations")
    p_rules_sub = p_rules.add_subparsers(dest="rules_command", required=True)
    p_rc = p_rules_sub.add_parser("check", help="compile-check the rule pack")
    p_rc.add_argument("--rules", default=None)
    p_rc.add_argument("--format", choices=["human", "json"], default="human")
    p_rc.set_defaults(func=cmd_rules_check)

    p_verify = sub.add_parser("verify-report", help="validate a report against its schema")
    p_verify.add_argument("report")
    p_verify.add_argument("--format", choices=["human", "json"], default="human")
    p_verify.set_defaults(func=cmd_verify_report)

    p_ver = sub.add_parser("version", help="print version")
    p_ver.set_defaults(func=_cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse --help/--version call sys.exit(0); propagate cleanly.
        if exc.code in (0, None):
            raise
        return EXIT_USAGE
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: internal failure: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
