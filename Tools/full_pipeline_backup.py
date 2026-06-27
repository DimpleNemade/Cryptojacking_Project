#!/usr/bin/env python3
import subprocess
import os
import sys

def run_cmd(cmd):
    """Run a shell command and optionally save its output."""
    print(f"[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

def run_pipeline(memory_path, case_id):
    reports_dir = "Reports"
    os.makedirs(reports_dir, exist_ok=True)

    # YARA Scan
    yara_out = run_cmd(f"yara -r YARA_Rules/miner_rules.yar {memory_path}")
    with open(f"{reports_dir}/{case_id}_yara.txt", "w") as f:
        f.write(yara_out)

    # STRINGS Extraction
    strings_out = run_cmd(f"strings {memory_path} | head -n 200")
    with open(f"{reports_dir}/{case_id}_strings.txt", "w") as f:
        f.write(strings_out)

    # SHA256 Hash
    hash_out = run_cmd(f"sha256sum {memory_path}")
    with open(f"{reports_dir}/{case_id}_hash.txt", "w") as f:
        f.write(hash_out)

    # Simple detection flag based on YARA output
    miner_detected = "YES" if "miner_indicators" in yara_out else "NO"
    summary_path = f"{reports_dir}/{case_id}_summary.txt"
    with open(summary_path, "w") as f:
        f.write(f"CASE_ID={case_id}\n")
        f.write(f"MEMORY_DUMP={memory_path}\n")
        f.write(f"MINER_DETECTED={miner_detected}\n")
        f.write(f"YARA_REPORT={reports_dir}/{case_id}_yara.txt\n")
        f.write(f"STRINGS_REPORT={reports_dir}/{case_id}_strings.txt\n")
        f.write(f"HASH_REPORT={reports_dir}/{case_id}_hash.txt\n")
   
    print(f"[+] Pipeline complete. Rsults saved under {reports_dir}/")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 full_pipeline.py <memory_dump> <case_id>")
        sys.exit(1)

    memory_path = sys.argv[1]
    case_id = sys.argv[2]
    run_pipeline(memory_path, case_id)

