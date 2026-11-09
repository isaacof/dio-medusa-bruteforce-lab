# 02 — Reconhecimento com Nmap

## Objetivo

Identificar hosts ativos, portas abertas e versões de serviço antes de qualquer tentativa de autenticação. O reconhecimento direciona o resto do teste: não faz sentido atacar FTP se a porta 21 estiver fechada.

## Comando utilizado

```bash
nmap -sV -Pn -T4 \
  -p21,22,23,25,80,139,445,3306,5432 \
  192.168.56.102 \
  -oN logs/01-nmap-servicos.txt
```

| Opção | Função |
|---|---|
| `-sV` | Detecta versão dos serviços |
| `-Pn` | Assume host ativo (não depende de ICMP) |
| `-T4` | Timing agressivo, adequado a rede local |
| `-p` | Lista de portas relevantes |
| `-oN` | Salva a saída em formato normal |

## Resultado

```text
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
```

- **9 portas abertas**
- Host: `metasploitable.localdomain`
- MAC: `08:00:27:D9:31:14` (VirtualBox)

## Análise serviço por serviço

### 21/tcp — vsftpd 2.3.4

Versão famosa por conter um **backdoor** introduzido no código-fonte (CVE-2011-2523). Mesmo sem explorar o backdoor, o serviço aceita autenticação por senha e não possui bloqueio por tentativas — alvo ideal para força bruta.

**Risco:** alto. Serviço legado, sem criptografia e com vulnerabilidade crítica conhecida.

### 22/tcp — OpenSSH 4.7p1

Versão antiga. Não foi alvo deste exercício, mas também permite autenticação por senha e deveria ser protegido com chaves e MFA.

### 23/tcp — Telnet

Protocolo em **texto claro**. Credenciais trafegam sem criptografia. Deveria estar desabilitado em qualquer ambiente real.

### 25/tcp — Postfix

Superfície adicional. Pode permitir enumeração de usuários (`VRFY`) e relay aberto se mal configurado.

### 80/tcp — Apache 2.2.8 + DVWA

Aplicação web intencionalmente vulnerável. O DVWA tem formulário de login e uma página de força bruta em `/vulnerabilities/brute/`.

### 139/445 — Samba 3.0.20

Compartilhamento SMB antigo, com **sessão nula habilitada**. Permite enumerar usuários e compartilhamentos sem credenciais.

### 3306/5432 — MySQL e PostgreSQL

Bancos expostos na rede. Não foram atacados neste escopo, mas representam risco elevado se usarem credenciais padrão.

## Conclusão do reconhecimento

O alvo expõe **serviços legados, sem criptografia e com credenciais padrão**. Três frentes foram escolhidas para o exercício:

1. **FTP** — autenticação simples, sem lockout.
2. **SMB** — enumeração de usuários + spraying.
3. **HTTP/DVWA** — formulário web sem proteção.

## Mitigação imediata

- Fechar portas não utilizadas (Telnet, FTP, bancos expostos).
- Atualizar vsftpd, Samba, Apache e OpenSSH.
- Substituir Telnet por SSH e FTP por SFTP.
- Segmentar a rede e aplicar firewall de host.

---

Anterior: [01 — Ambiente](01-ambiente.md) · Voltar ao [README](../README.md) · Próximo: [03 — FTP](03-ftp.md)
