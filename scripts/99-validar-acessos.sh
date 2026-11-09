#!/usr/bin/env bash
# 99 — Validação consolidada dos acessos obtidos.
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

{
  echo "== $(date -Is) =="
  echo
  echo "-- FTP: msfadmin/msfadmin --"
  curl -s --max-time 10 "ftp://msfadmin:msfadmin@$TARGET/" | head -10
  echo
  echo "-- SMB: msfadmin/msfadmin (share tmp) --"
  smbclient "//$TARGET/tmp" -U 'msfadmin%msfadmin' -c 'ls' 2>&1 | head -12
} 2>&1 | tee logs/99-validacao.txt
