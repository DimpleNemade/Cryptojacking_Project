#!/usr/bin/env bash
set -e

if [ $# -ne 2 ]; then
echo "Usage: $0 <dump_file> <case_id>"
exit 1
fi

DUMP="$1"
CASE="$2"

echo "[+] Running YARA scans..."
yara -r YARA_Rules/miner_rules.yar "$DUMP" | tee "Reports/${CASE}_yara.txt"

echo "[+] Extracting strings..."
strings "$DUMP" | grep -i -E "stratum|xmrig|miner" | tee "Reports/${CASE}_strings.txt"

echo "[+] Computing SHA256..."
sha256sum "$DUMP" | tee "Reports/${CASE}_hash.txt"

echo "[+] Pipeline complete: Reports saved in Reports/${CASE}_*.txt"

