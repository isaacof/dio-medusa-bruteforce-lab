#!/usr/bin/env bash
# 00 — Verifica ferramentas e conectividade do laboratório.
# Uso: TARGET=192.168.56.102 ./scripts/00-verificar-ambiente.sh
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

{
  echo "== $(date -Is) =="
  echo "Alvo: $TARGET"
  echo
  echo "-- Ferramentas --"
  for t in medusa nmap enum4linux smbclient curl ftp; do
    if command -v "$t" >/dev/null 2>&1; then
      printf 'OK    %-12s %s\n' "$t" "$(command -v "$t")"
    else
      printf 'FALTA %-12s (instale antes de continuar)\n' "$t"
    fi
  done
  echo
  echo "-- Conectividade (ping) --"
  ping -c 2 -W 1 "$TARGET" | tail -2
  echo
  echo "-- Portas principais --"
  nmap -Pn -T4 -p21,22,80,139,445 "$TARGET" | sed -n '/PORT/,/^$/p'
} 2>&1 | tee logs/00-ambiente.txt
