#!/usr/bin/env bash
# 03 — Enumeração SMB: shares e usuários (sessão nula).
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

echo "== Shares SMB (anônimo) =="
smbclient -L "//$TARGET" -N 2>&1 | tee logs/03-smb-shares.txt

echo
echo "== Usuários SMB (enum4linux) =="
enum4linux -U "$TARGET" > logs/03-smb-users-raw.txt 2>&1
grep -oP 'Account: \K\S+' logs/03-smb-users-raw.txt | sort -u | tee logs/03-smb-users.txt
echo
echo "Total: $(wc -l < logs/03-smb-users.txt) usuários enumerados."
