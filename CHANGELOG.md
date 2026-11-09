# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.
O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.0.0] — 2026-11-09

### Adicionado

- Laboratório isolado com Kali Linux, Metasploitable 2 e DVWA.
- Ataques controlados com Medusa: FTP, SMB (password spraying) e formulário web.
- Validação independente dos acessos com `curl` e `smbclient`.
- Oito guias técnicos em português e resumo em inglês (`README.en.md`).
- Automação de triagem SOC em Python (`scripts/06-soc-triage.py`):
  - relatório em Markdown;
  - JSON normalizado para SIEM/SOAR;
  - prompt de IA sanitizado, com credenciais redigidas por padrão.
- Regras de detecção em Sigma (FTP, SMB spraying, web) e Wazuh.
- Testes unitários e de integração (`tests/`).
- CI no GitHub Actions: ShellCheck, sintaxe Python, testes, validação de links e geração do relatório.
- Runner opcional de análise local com Ollama (`scripts/08-ai-triage.sh`).
- `Makefile` com atalhos `lint`, `links`, `triage`, `test` e `all`.
- Evidências sanitizadas: logs, capturas de tela e wordlists de laboratório.
- Política de segurança (`SECURITY.md`), licença MIT e Dependabot para as actions.

### Segurança

- Nenhuma credencial real ou dado de terceiros foi utilizado.
- Todos os testes foram executados em rede host-only, sem exposição à internet.

[1.0.0]: https://github.com/isaacof/dio-medusa-bruteforce-lab/releases/tag/v1.0.0
