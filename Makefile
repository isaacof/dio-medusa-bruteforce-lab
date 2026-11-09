.PHONY: help all lint links test triage

PYTHON ?= python3

help:
	@echo "Alvos disponíveis:"
	@echo "  make triage  - gera reports/soc-triage.md, .json e ai-triage-prompt.md"
	@echo "  make links   - valida links relativos do README e da documentação"
	@echo "  make test    - executa os testes unitários"
	@echo "  make lint    - verifica a sintaxe dos scripts Python"
	@echo "  make all     - lint + links + triage + test"

all: lint links triage test

triage:
	$(PYTHON) scripts/06-soc-triage.py --source evidencias --out reports

links:
	$(PYTHON) scripts/07-validar-links.py

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	$(PYTHON) -m py_compile scripts/*.py tests/*.py
