# 06 — Mitigações e detecção

Este documento consolida os controles que teriam interrompido os três ataques e apresenta formas de **detectá-los** em ambiente real.

## 1. Mapa ataque → controle

| Ataque | Como funciona | Controle que interrompe |
|---|---|---|
| Força bruta em FTP | Muitas senhas para um usuário | Bloqueio progressivo, fail2ban, SFTP, senha forte |
| Enumeração SMB | Sessão nula lista usuários/shares | `restrict anonymous = 2`, desabilitar SMBv1 |
| Password spraying | Uma senha para muitos usuários | Lockout por conta, MFA, senha forte, detecção por IP |
| Força bruta web | Muitas requisições ao formulário | Rate limiting, CAPTCHA, MFA, WAF |

## 2. Política de senhas

Recomendações alinhadas ao **NIST SP 800-63B**:

- Comprimento mínimo de **12 caracteres** (melhor 16+).
- Permitir frases-senha e caracteres especiais.
- **Não** exigir rotação periódica sem motivo.
- Bloquear senhas comuns e vazadas (listas tipo Have I Been Pwned).
- Comparar com a lista de senhas proibidas da organização.
- **MFA** em acessos remotos e administrativos.
- Password manager para senhas únicas.
- Nunca usar credenciais padrão.

## 3. Bloqueio e rate limiting

### FTP / SSH — fail2ban

```ini
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
```

### Aplicação web

- Limite por IP **e** por conta.
- Bloqueio temporário após 5–10 falhas.
- CAPTCHA progressivo.
- Backoff exponencial.
- Alertas para o time de segurança.

## 4. Hardening por serviço

### FTP

- [ ] Desativar FTP; usar SFTP/FTPS.
- [ ] Atualizar o vsftpd (2.3.4 tem backdoor — CVE-2011-2523).
- [ ] Remover contas padrão.
- [ ] Restringir por IP.
- [ ] Ativar logs e fail2ban.
- [ ] Aplicar chroot e menor privilégio.

### SMB

- [ ] Desabilitar SMBv1.
- [ ] Exigir SMB signing.
- [ ] `restrict anonymous = 2` (Samba).
- [ ] Bloquear sessões nulas.
- [ ] Remover contas de serviço antigas.
- [ ] Aplicar menor privilégio (sem `ADMIN$` para usuários comuns).
- [ ] Monitorar 4625/4771 e logs do Samba.
- [ ] Segmentar 139/445.

### Web

- [ ] Rate limiting e lockout.
- [ ] MFA para administradores.
- [ ] CAPTCHA após falhas.
- [ ] Mensagens de erro genéricas.
- [ ] Hash Argon2id/bcrypt.
- [ ] POST + HTTPS.
- [ ] WAF.
- [ ] Monitorar picos de login.
- [ ] Não expor DVWA ou apps de treino.

## 5. Detecção

### FTP

```bash
grep -i "failed login\|authentication failure" /var/log/vsftpd.log /var/log/auth.log
```

Sinal de alerta: muitas falhas do mesmo IP em curto intervalo.

### SMB

- Windows: eventos **4625** (logon falho), **4771** (Kerberos), **4776** (NTLM).
- Samba: aumentar `log level` e monitorar falhas de autenticação.
- Sinal de alerta: um IP falhando em **muitos usuários diferentes** (spraying).

### Web

```bash
grep "vulnerabilities/brute" /var/log/apache2/access.log \
  | awk '{print $1}' | sort | uniq -c | sort -nr | head
```

Sinal de alerta: muitas requisições `200` com `username`/`password` na URL, vindas do mesmo IP.

### Correlação

Um ataque real raramente usa um único vetor. Correlacione:

- falhas de login em FTP + SMB + web no mesmo intervalo;
- um IP que enumera serviços e depois autentica;
- horários fora do expediente;
- aumento de tráfego para portas incomuns.

## 6. Segmentação e arquitetura

- Colocar serviços administrativos em VLAN separada.
- Bloquear SMB (139/445) e FTP (21) na borda.
- Usar **VPN** ou **bastion host** para administração.
- Aplicar **zero trust**: nenhum serviço confiável por padrão.
- Manter o Metasploitable/DVWA **isolados** em laboratório.

## 7. Gestão de vulnerabilidades

- Inventário de serviços e versões.
- Scanner periódico (Nessus, OpenVAS, Qualys).
- Priorização por risco (CVSS + exposição).
- Patch management com prazo definido.
- Testes de intrusão anuais ou após mudanças relevantes.
- Revisão de configurações (CIS Benchmarks).

## 8. Resposta a incidentes

1. **Identificar** — alertas de falhas em massa, contas bloqueadas, picos de tráfego.
2. **Conter** — bloquear IP, desabilitar conta, isolar host.
3. **Erradicar** — corrigir configuração, trocar senhas, aplicar patch.
4. **Recuperar** — restaurar serviços e monitorar.
5. **Aprender** — registrar lições e ajustar controles.

## 9. Checklist rápido para qualquer ambiente

- [ ] Nenhuma credencial padrão ativa.
- [ ] MFA em acessos administrativos.
- [ ] Bloqueio após N falhas.
- [ ] Rate limiting em formulários.
- [ ] Serviços não utilizados desligados.
- [ ] Versões suportadas e atualizadas.
- [ ] SMBv1 desabilitado e sessão nula bloqueada.
- [ ] Logs centralizados e alertas configurados.
- [ ] Rede segmentada.
- [ ] Plano de resposta a incidentes testado.

---

Anterior: [05 — DVWA](05-dvwa.md) · Voltar ao [README](../README.md) · Próximo: [07 — Conclusão](07-conclusao.md)
