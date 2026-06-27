#!/bin/bash

set -e

if [ $# -ne 1 ]; then
echo "Usage: $0 <dump_file>"
exit 1
fi

DUMP=$1

echo "[*] Running YARA scans..."
for rule in YARA_Rules/*.yar; do
name=$(basename "$rule")
echo "[*] Scanning with $name"
yara -r "$rule" "$DUMP" > "Reports/${name%.yar}_scan.txt"
done

echo "[*] ALL YARA scans completed."

