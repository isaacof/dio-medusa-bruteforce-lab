# Documentação — Laboratório de Cibersegurança com Medusa

Índice dos guias técnicos do projeto. A leitura foi organizada para levar do ambiente até a detecção e a automação.

| # | Documento | O que cobre |
|---|---|---|
| 01 | [Montagem do ambiente](01-ambiente.md) | VirtualBox, rede host-only, Kali, Metasploitable 2 e DVWA |
| 02 | [Reconhecimento](02-reconhecimento.md) | Nmap, serviços expostos e leitura de risco |
| 03 | [FTP](03-ftp.md) | Força bruta com Medusa, validação e mitigação |
| 04 | [SMB](04-smb.md) | Enumeração, sessão nula, password spraying e hardening |
| 05 | [DVWA](05-dvwa.md) | Sessão web, módulo `web-form`, validação e defesas |
| 06 | [Mitigações](06-mitigacoes.md) | Controles preventivos, detectivos e resposta a incidentes |
| 07 | [Conclusão](07-conclusao.md) | Resultados, aprendizados, dificuldades e próximos passos |
| 08 | [SOC e automação com IA](08-soc-e-automacao.md) | MITRE ATT&CK, Sigma, SPL, KQL, Wazuh e triagem com Python |

## Ordem sugerida

1. **Entender o ambiente:** 01 e 02.
2. **Executar os ataques:** 03, 04 e 05.
3. **Defender e detectar:** 06 e 08.
4. **Fechar o ciclo:** 07.

## O que você encontra em cada fase

- **Ofensiva autorizada:** comandos reproduzíveis, wordlists pequenas e validação independente.
- **Defesa:** mitigação por vetor, hardening de FTP/SMB/Web e checklist de resposta.
- **SOC:** fontes de log, regras de detecção, mapeamento MITRE ATT&CK e métricas.
- **Automação:** script em Python que gera relatório, JSON para SIEM e prompt sanitizado para IA.

## Relatórios gerados

- [Triagem SOC em Markdown](../reports/soc-triage.md)
- [Triagem SOC em JSON](../reports/soc-triage.json)
- [Prompt para análise assistida por IA](../reports/ai-triage-prompt.md)

## Convenções

- Todos os testes foram feitos em **rede host-only**, sem alvos reais.
- Credenciais de laboratório são públicas e intencionais; nenhuma credencial real foi usada.
- Comandos marcados como ofensivos exigem **autorização escrita** em qualquer ambiente real.

---

Voltar ao [README](../README.md)
