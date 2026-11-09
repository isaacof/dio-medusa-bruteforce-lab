#!/usr/bin/env bash
# 08 — Executa a triagem assistida por IA localmente com Ollama.
# Requer: Ollama instalado e o modelo baixado (ex.: ollama pull llama3.2).
# A saída é gerada localmente; nenhum dado sai da máquina.
set -euo pipefail

BASE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE"

MODEL="${OLLAMA_MODEL:-llama3.2}"
PROMPT="reports/ai-triage-prompt.md"
OUT="reports/ai-triage-output.md"

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama não encontrado. Instale em https://ollama.com e rode: ollama pull $MODEL" >&2
  exit 1
fi

if [ ! -f "$PROMPT" ]; then
  echo "Prompt não encontrado. Rode primeiro: python3 scripts/06-soc-triage.py" >&2
  exit 1
fi

echo "Modelo: $MODEL"
echo "Prompt: $PROMPT"
echo "A saída da IA é uma sugestão: revise antes de usar em qualquer decisão."
echo

ollama run "$MODEL" < "$PROMPT" | tee "$OUT"

echo
echo "Saída salva em $OUT"
