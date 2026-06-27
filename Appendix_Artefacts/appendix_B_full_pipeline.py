#!/usr/bin/env python3

import argparse
import os
import sys
import shlex
import subprocess
from pathlib import Path

def run_cmd(args: list[str]) -> str:
    """
    Run a command without using the shell and return stdout as text.
    stderr is printed but does not stop execution.
    """
    printable = " ".join(shlex.quote(a) for a in args)
    print(f"[+] Running: {printable}")
    result = subprocess.run(args, capture_output=True, text=True)
    if result.stderr:
        # Show stderr but don't necessarily fail
        err = result.stderr.strip()
        if err:
            print(err, file=sys.stderr)
    return result.stdout

def run_pipeline(memory_path: str, case_id: str) -> None:
    """
    Run YARA, strings and SHA256 over a memory dump and write reports.
    Compute a confidence score, risk level and a short explanation.
    """

    mem = Path(memory_path)
    if not mem.exists():
        print(f"[!] ERROR: Memory dump not found: {mem}")
        sys.exit(1)

    reports_root = Path("Reports")
    case_dir = reports_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Case directory: {case_dir.resolve()}")

    #--- YARA scan ------------
    yara_rules = Path("YARA_Rules") / "miner_rules.yar"
    if not yara_rules.exists():
        print(f"[!] WARNING: YARA rules fine not found: {yara_rules}", file=sys.stderr)
        yara_out = ""
    else:
        yara_cmd = ["yara", "-r", "-s", str(yara_rules), str(mem)]
        yara_out = run_cmd(yara_cmd)

    yara_report_path = case_dir / f"{case_id}_yara.txt"
    yara_report_path.write_text(yara_out, encoding="utf-8", errors="ignore")

    #--- STRINGS extraction ----------
    strings_cmd = ["strings", str(mem)]
    strings_full = run_cmd(strings_cmd)
    strings_report_path = case_dir / f"{case_id}_strings.txt"
    strings_report_path.write_text(strings_full, encoding="utf-8", errors="ignore")
    # Limit in-memory sample to keep scoring fast
    strings_sample = "\n".join(strings_full.splitlines()[:500])

    #--- SHA256 hash ----------
    hash_cmd = ["sha256sum", str(mem)]
    hash_out = run_cmd(hash_cmd)
    hash_report_path = case_dir / f"{case_id}_hash.txt"
    hash_report_path.write_text(hash_out, encoding="utf-8", errors="ignore")

    #--- confidence scoring -----------
    confidence = 0
    reasons: list[str] = []

    # Rule-based signals
    if "xmrig_indicators" in yara_out:
        confidence += 2
        reasons.append("Xmrig rule matched")

    if "generic_stratum_miner" in yara_out:
        confidence += 2
        reasons.append("Generic startum mining rule matched")

    if "wallet_like_strings" in yara_out:
        confidence += 1
        reasons.append("Wallet-like YARA hit")

    # String-based backup checks
    if "xmrig" in yara_out or "xmrig" in strings_sample:
        confidence += 1
        reasons.append("Found 'xmrig' string")

    if "stratum+tcp" in yara_out or "startum+tcp" in strings_sample:
        confidence += 1
        reasons.append("Found 'stratum+tcp'")

    if "stratum+ssl" in yara_out or "stratum+ssl" in strings_sample:
        confidence += 1
        reasons.append("Found 'stratum+ssl'")

    if ".pool" in strings_sample or "mining" in strings_sample:
        confidence += 1
        reasons.append("Pool/mining domain hint in strings")

    if "wallet=" in yara_out or "wallet=" in strings_sample:
        confidence += 1
        reasons.append("Wallet= style string in memory")

    # Derive MINER_DETECTED and risk level
    miner_detected = "YES" if confidence >= 2 else "NO"

    if confidence == 0:
        risk_level = "LOW"
    elif 1 <= confidence <= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    # Build explanation
    if reasons:
        explanation = "Indicators: " + "; ".join(reasons)
    else:
        explanation = "No strong miner indicators found in YARA output or strings sample."

    # --- summary file -----------
    summary_path = case_dir / f"{case_id}_summary.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"CASE_ID={case_id}\n")
        f.write(f"MEMORY_DUMP={mem.resolve()}\n")
        f.write(f"MINER_DETECTED={miner_detected}\n")
        f.write(f"CONFIDENCE_SCORE={confidence}\n")
        f.write(f"RISK_LEVEL={risk_level}\n")
        f.write(f"AI_EXPLANATION={explanation}\n")
        f.write(f"YARA_REPORT={yara_report_path.resolve()}\n")
        f.write(f"STRINGS_REPORT={strings_report_path.resolve()}\n")
        f.write(f"HASH_REPORT={hash_report_path.resolve()}\n")

    print(f"[+] Pipeline complete. Results saved under {case_dir}/")
    print(f"[+] Summary: {summary_path}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cryptominer detection pipeline over a memory dump."
    )
    parser.add_argument(
        "-m", "--memory",
        required=True,
        help="Path to memory dump file (e.g. mem.raw)",
    )
    parser.add_argument(
        "-c", "--case-id",
        required=True,
        help="Case identifier (e.g. CASE001)",
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_pipeline(args.memory, args.case_id)
