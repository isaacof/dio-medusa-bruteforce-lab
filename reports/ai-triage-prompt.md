# Prompt de triagem assistida por IA

> Gerado automaticamente pelo laboratório. **Não contém credenciais.**
> Para logs reais, sanitize IPs, usuários e nomes de host antes de enviar a qualquer LLM.

## Contexto

Você é um assistente de análise de SOC. Receberá evidências normalizadas de um
laboratório isolado de força bruta. Sua função é apoiar a triagem, **não substituir**
a validação humana.

## Evidências

| ID | Horário | Host | Usuário | Serviço | Técnica | MITRE | Severidade |
|---|---|---|---|---|---|---|---|
| SOC-001 | 2026-11-09 18:03:50 | 192.168.56.102 | msfadmin | FTP | Força bruta de credenciais | T1110.001, T1078 | high |
| SOC-002 | 2026-11-09 18:03:57 | 192.168.56.102 | msfadmin | SMB | Password spraying | T1110.003, T1078 | critical |
| SOC-003 | 2026-11-09 18:03:57 | 192.168.56.102 | msfadmin | SMB | Força bruta direcionada | T1110.001, T1078 | critical |
| SOC-004 | 2026-11-09 18:06:46 | 192.168.56.102 | admin | HTTP | Força bruta em formulário web | T1110.001, T1078 | critical |

### Serviços observados

| Porta | Serviço | Versão | Risco |
|---:|---|---|---|
| 21 | ftp | vsftpd 2.3.4 | Backdoor conhecido (CVE-2011-2523) e protocolo sem criptografia |
| 22 | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) | Versão antiga; autenticação por senha habilitada |
| 23 | telnet | Linux telnetd | Protocolo em texto claro |
| 25 | smtp | Postfix smtpd |  |
| 80 | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | Versão sem suporte |
| 139 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |  |
| 445 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |  |
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 | Versão antiga exposta na rede |
| 5432 | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 |  |

### Enumeração

- Usuários enumerados via SMB: 35
- Compartilhamentos: print$, tmp, opt, IPC$, ADMIN$

## Tarefa

1. Resuma o incidente em até 5 linhas.
2. Confirme ou reclassifique a severidade de cada achado, justificando.
3. Mapeie cada achado para MITRE ATT&CK.
4. Proponha três regras de detecção (Sigma, Splunk SPL ou KQL).
5. Liste cinco perguntas de triagem que faltam responder.
6. Sugira contenção, erradicação e recuperação em ordem de prioridade.

## Formato de saída (JSON)

```json
{
  "resumo": "...",
  "achados": [
    {"id": "SOC-001", "severidade": "critical|high|medium|low", "justificativa": "...", "mitre": ["T1110.001"]}
  ],
  "regras_deteccao": [{"nome": "...", "linguagem": "sigma|spl|kql", "regra": "..."}],
  "perguntas_triagem": ["..."],
  "resposta": {"contencao": ["..."], "erradicacao": ["..."], "recuperacao": ["..."]}
}
```

## Guardrails

- Use **somente** os dados fornecidos; não invente IPs, horários ou usuários.
- Não solicite nem reproduza credenciais.
- Marque hipóteses como hipóteses e indique o que precisa de validação.
- Se faltar evidência, diga explicitamente o que falta.
- Responda em português do Brasil.
