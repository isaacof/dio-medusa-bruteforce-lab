#!/usr/bin/env bash
# 01 — Reconhecimento de serviços com Nmap.
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

nmap -sV -Pn -T4 \
  -p21,22,23,25,80,139,445,3306,5432 \
  "$TARGET" -oN logs/01-nmap-servicos.txt \
  2>&1 | tee logs/01-nmap-console.txt
