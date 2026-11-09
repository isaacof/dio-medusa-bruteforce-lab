# 03 — FTP: força bruta com Medusa

## O protocolo

O FTP (File Transfer Protocol) autentica com usuário e senha em **texto claro**. Não possui mecanismos nativos de bloqueio, MFA ou limitação de tentativas. Por isso, é um alvo clássico de força bruta quando exposto.

No Metasploitable 2, o serviço é o **vsftpd 2.3.4**, versão que ficou conhecida pelo backdoor CVE-2011-2523.

## Preparação

Wordlists usadas:

- [`wordlists/users.txt`](../wordlists/users.txt) — 7 usuários
- [`wordlists/passwords.txt`](../wordlists/passwords.txt) — 12 senhas

São listas pequenas de propósito: o objetivo é demonstrar o conceito, não esgotar um dicionário real.

## Comando

```bash
medusa -h 192.168.56.102 \
  -U wordlists/users.txt \
  -P wordlists/passwords.txt \
  -M ftp \
  -t 1 -f \
  -O logs/02-ftp-medusa.log
```

### O que cada opção faz

| Opção | Descrição |
|---|---|
| `-h` | Endereço do alvo |
| `-U` | Arquivo com lista de usuários |
| `-P` | Arquivo com lista de senhas |
| `-M ftp` | Módulo FTP do Medusa |
| `-t 1` | Uma thread por vez (resultado determinístico) |
| `-f` | Interrompe ao encontrar a primeira credencial válida |
| `-O` | Salva o log completo da execução |

## Execução

O Medusa testa o produto cartesiano usuário × senha. Com 7 usuários e 12 senhas, o espaço total é de 84 combinações.

Na execução real, a credencial foi encontrada na **16ª tentativa**:

```text
2026-11-09 18:03:50 ACCOUNT FOUND: [ftp] Host: 192.168.56.102
  User: msfadmin Password: msfadmin [SUCCESS]
```

### Linha do tempo

| Evento | Horário |
|---|---|
| Início | 18:03:05 |
| Credencial encontrada | 18:03:50 |
| Duração | ~45 segundos |

O vsftpd aplica um atraso entre tentativas, o que explica a lentidão relativa. Ainda assim, com uma wordlist maior e múltiplas threads, o ataque continuaria viável — e credenciais padrão caem nas primeiras tentativas.

## Validação

Encontrar a senha não é suficiente; é preciso confirmar o acesso com outra ferramenta:

```bash
curl -s ftp://msfadmin:msfadmin@192.168.56.102/
```

Saída:

```text
drwxr-xr-x    6 1000     1000         4096 Apr 28  2010 vulnerable
```

O usuário autenticado lista o diretório `vulnerable`, que contém a aplicação web do Metasploitable. Isso mostra que o impacto vai além do FTP: o acesso pode levar à manipulação de arquivos servidos pelo Apache.

## Por que o ataque funcionou?

1. **Credencial padrão** `msfadmin:msfadmin`, documentada publicamente.
2. **Ausência de bloqueio** por tentativas.
3. **Serviço exposto** sem necessidade.
4. **Versão vulnerável** e sem criptografia.
5. **Permissões excessivas** do usuário no sistema de arquivos.

## Mitigações

### Preventivas

- Desativar o FTP e migrar para **SFTP** (SSH) ou **FTPS**.
- Atualizar o vsftpd; a versão 2.3.4 possui backdoor conhecido.
- Remover contas padrão e exigir troca de senha no primeiro acesso.
- Aplicar **fail2ban** ou bloqueio progressivo.
- Restringir acesso por IP e segmentar o serviço.
- Usar senhas longas e únicas, com MFA quando o protocolo permitir.

### Detectivas

- Monitorar `/var/log/vsftpd.log` e `/var/log/auth.log`.
- Alertar para múltiplas falhas de autenticação do mesmo IP.
- Correlacionar com tentativas em outros serviços (SSH, SMB, web).

### Exemplo de jail do fail2ban

```ini
[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 3
bantime  = 3600
findtime = 600
```

## Evidências

- Log: [`evidencias/ftp/02-ftp-medusa.log`](../evidencias/ftp/02-ftp-medusa.log)
- Saída do console: [`evidencias/ftp/02-ftp-console.txt`](../evidencias/ftp/02-ftp-console.txt)
- Validação: [`evidencias/ftp/02-ftp-validacao.txt`](../evidencias/ftp/02-ftp-validacao.txt)
- Captura: [`evidencias/images/06-medusa-ftp.png`](../evidencias/images/06-medusa-ftp.png)

---

Anterior: [02 — Reconhecimento](02-reconhecimento.md) · Voltar ao [README](../README.md) · Próximo: [04 — SMB](04-smb.md)
