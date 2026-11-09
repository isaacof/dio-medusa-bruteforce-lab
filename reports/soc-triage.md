# Relatório de Triagem SOC — Laboratório Medusa

> Gerado automaticamente em **2026-11-09 21:45:51 UTC** a partir de `evidencias`.
> Laboratório isolado em rede host-only. Nenhum alvo real foi consultado.

## Resumo executivo

- **4** evento(s) de autenticação bem-sucedida identificado(s) nas evidências.
- **1** host(s) envolvido(s): `192.168.56.102`.
- **3** serviço(s) comprometido(s): FTP, HTTP, SMB.
- **35** usuário(s) enumerado(s) via SMB e **5** compartilhamento(s) listado(s).
- Severidade mais alta: **🔴 Crítica**.
- Credenciais: redigidas neste relatório.

## Achados

| ID | Horário | Host | Usuário | Técnica | MITRE | Severidade | Evidência |
|---|---|---|---|---|---|---|---|
| SOC-001 | 2026-11-09 18:03:50 | `192.168.56.102` | `msfadmin` | Força bruta de credenciais | T1110.001, T1078 | 🟠 Alta | `ftp/02-ftp-medusa.log` |
| SOC-002 | 2026-11-09 18:03:57 | `192.168.56.102` | `msfadmin` | Password spraying | T1110.003, T1078 | 🔴 Crítica | `smb/04-smb-spray.log` |
| SOC-003 | 2026-11-09 18:03:57 | `192.168.56.102` | `msfadmin` | Força bruta direcionada | T1110.001, T1078 | 🔴 Crítica | `smb/04-smb-brute.log` |
| SOC-004 | 2026-11-09 18:06:46 | `192.168.56.102` | `admin` | Força bruta em formulário web | T1110.001, T1078 | 🔴 Crítica | `dvwa/05-dvwa-medusa.log` |

## Linha do tempo

- `2026-11-09 18:03:50` — Força bruta de credenciais em **FTP:21** (`192.168.56.102`), usuário `msfadmin`.
- `2026-11-09 18:03:57` — Password spraying em **SMB:445** (`192.168.56.102`), usuário `msfadmin`.
- `2026-11-09 18:03:57` — Força bruta direcionada em **SMB:445** (`192.168.56.102`), usuário `msfadmin`.
- `2026-11-09 18:06:46` — Força bruta em formulário web em **HTTP:80** (`192.168.56.102`), usuário `admin`.

## Serviços observados no reconhecimento

| Porta | Serviço | Versão | Risco |
|---:|---|---|---|
| 21 | ftp | vsftpd 2.3.4 | Backdoor conhecido (CVE-2011-2523) e protocolo sem criptografia |
| 22 | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) | Versão antiga; autenticação por senha habilitada |
| 23 | telnet | Linux telnetd | Protocolo em texto claro |
| 25 | smtp | Postfix smtpd | — |
| 80 | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | Versão sem suporte |
| 139 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | — |
| 445 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | — |
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 | Versão antiga exposta na rede |
| 5432 | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 | — |

## Enumeração SMB

- Usuários enumerados: **35**
- Amostra: `backup`, `bin`, `bind`, `daemon`, `dhcp`, `distccd`, `ftp`, `games`, `gnats`, `irc`
- Compartilhamentos: `print$`, `tmp`, `opt`, `IPC$`, `ADMIN$`

## Cobertura MITRE ATT&CK

| Técnica | ID | Achados |
|---|---|---:|
| Valid Accounts | T1078 | 4 |
| Password Guessing | T1110.001 | 3 |
| Password Spraying | T1110.003 | 1 |

## Recomendações de detecção

### Força bruta de credenciais (FTP)

**Sinal:** Múltiplas falhas de autenticação FTP do mesmo IP em curto intervalo.

```spl
index=linux sourcetype=vsftpd OR sourcetype=linux_secure "authentication failure" OR "FAIL LOGIN" | stats count by src_ip, user | where count > 5
```

```kql
event.dataset:(vsftpd.log or system.auth) and event.outcome:"failure" | stats count by source.ip, user.name | where count > 5
```

### Password spraying (SMB)

**Sinal:** Mesmo IP falhando em muitos usuários diferentes (padrão de spraying).

```spl
index=windows EventCode=4625 | stats dc(TargetUserName) as usuarios, count by IpAddress | where usuarios > 5
```

```kql
event.code:4625 | stats users=dcount(user.name) by source.ip | where users > 5
```

### Força bruta direcionada (SMB)

**Sinal:** Muitas falhas para o mesmo usuário em curto intervalo.

```spl
index=windows EventCode=4625 | stats count by TargetUserName, IpAddress | where count > 10
```

```kql
event.code:4625 | stats count by user.name, source.ip | where count > 10
```

### Força bruta em formulário web (HTTP)

**Sinal:** Picos de requisições ao endpoint de login, muitas com resposta 200/401.

```spl
index=web sourcetype=apache_access "/dvwa/vulnerabilities/brute/" | stats count by clientip, status | where count > 20
```

```kql
url.path:"/dvwa/vulnerabilities/brute/" | stats count by source.ip, http.response.status_code | where count > 20
```

## Perguntas de triagem

1. O IP de origem é conhecido e pertence ao inventário?
2. Quantas contas foram tentadas e quantas obtiveram sucesso?
3. Houve acesso a compartilhamentos administrativos ou dados sensíveis?
4. O mesmo IP aparece em outros serviços no mesmo intervalo?
5. Existe MFA, lockout ou rate limiting no serviço afetado?
6. A conta comprometida é privilegiada ou de serviço?

## Limitações

- Análise baseada apenas nas evidências versionadas; não há telemetria de endpoint.
- Os horários refletem o relógio da VM atacante.
- Falsos positivos são possíveis; toda detecção deve ser validada por um analista.
- O laboratório usa credenciais padrão e não representa um ambiente de produção.

---

Gerado por [`scripts/06-soc-triage.py`](../scripts/06-soc-triage.py).
